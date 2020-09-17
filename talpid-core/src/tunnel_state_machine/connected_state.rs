use super::{
    AfterDisconnect, ConnectingState, DisconnectingState, ErrorState, EventConsequence,
    SharedTunnelStateValues, TunnelCommand, TunnelState, TunnelStateTransition, TunnelStateWrapper,
};
use crate::{
    firewall::FirewallPolicy,
    tunnel::{CloseHandle, TunnelEvent, TunnelMetadata},
};
#[cfg(windows)]
use crate::{
    split_tunnel::{self, SplitTunnel},
    winnet::{self, get_best_default_route, interface_luid_to_ip, WinNetAddrFamily},
};
use futures01::{
    sync::{mpsc, oneshot},
    Async, Future, Stream,
};
#[cfg(windows)]
use std::{
    ffi::OsStr,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};
use talpid_types::{
    net::TunnelParameters,
    tunnel::{ErrorStateCause, FirewallPolicyError},
    BoxedError, ErrorExt,
};

#[cfg(windows)]
use crate::tunnel::TunnelMonitor;


pub struct ConnectedStateBootstrap {
    pub metadata: TunnelMetadata,
    pub tunnel_events: mpsc::UnboundedReceiver<TunnelEvent>,
    pub tunnel_parameters: TunnelParameters,
    pub tunnel_close_event: Option<oneshot::Receiver<Option<ErrorStateCause>>>,
    pub close_handle: Option<CloseHandle>,
}

/// The tunnel is up and working.
pub struct ConnectedState {
    metadata: TunnelMetadata,
    tunnel_events: mpsc::UnboundedReceiver<TunnelEvent>,
    tunnel_parameters: TunnelParameters,
    tunnel_close_event: Option<oneshot::Receiver<Option<ErrorStateCause>>>,
    close_handle: Option<CloseHandle>,
}

impl ConnectedState {
    fn from(bootstrap: ConnectedStateBootstrap) -> Self {
        ConnectedState {
            metadata: bootstrap.metadata,
            tunnel_events: bootstrap.tunnel_events,
            tunnel_parameters: bootstrap.tunnel_parameters,
            tunnel_close_event: bootstrap.tunnel_close_event,
            close_handle: bootstrap.close_handle,
        }
    }

    fn set_firewall_policy(
        &self,
        shared_values: &mut SharedTunnelStateValues,
    ) -> Result<(), FirewallPolicyError> {
        let policy = self.get_firewall_policy(shared_values);
        shared_values
            .firewall
            .apply_policy(policy)
            .map_err(|error| {
                log::error!(
                    "{}",
                    error.display_chain_with_msg(
                        "Failed to apply firewall policy for connected state"
                    )
                );
                #[cfg(windows)]
                match error {
                    crate::firewall::Error::ApplyingConnectedPolicy(policy_error) => policy_error,
                    _ => FirewallPolicyError::Generic,
                }
                #[cfg(not(windows))]
                FirewallPolicyError::Generic
            })
    }

    fn get_firewall_policy(&self, shared_values: &SharedTunnelStateValues) -> FirewallPolicy {
        FirewallPolicy::Connected {
            peer_endpoint: self.tunnel_parameters.get_next_hop_endpoint(),
            tunnel: self.metadata.clone(),
            allow_lan: shared_values.allow_lan,
            #[cfg(windows)]
            relay_client: TunnelMonitor::get_relay_client(
                &shared_values.resource_dir,
                &self.tunnel_parameters,
            ),
            #[cfg(target_os = "linux")]
            use_fwmark: self.tunnel_parameters.get_proxy_endpoint().is_none(),
        }
    }

    #[cfg(target_os = "windows")]
    pub unsafe extern "system" fn split_tunnel_default_route_change_handler(
        event_type: winnet::WinNetDefaultRouteChangeEventType,
        address_family: WinNetAddrFamily,
        default_route: winnet::WinNetDefaultRoute,
        ctx: *mut libc::c_void,
    ) {
        // Update the "internet interface" IP when best default route changes
        let ctx = &mut *(ctx as *mut SplitTunnelDefaultRouteChangeHandlerContext);

        let result = match event_type {
            winnet::WinNetDefaultRouteChangeEventType::DefaultRouteChanged => {
                let ip = interface_luid_to_ip(address_family.clone(), default_route.interface_luid);

                // TODO: Should we block here?
                let ip = match ip {
                    Ok(Some(ip)) => ip,
                    Ok(None) => {
                        log::error!("Failed to obtain new default route address: none found",);
                        // Early return
                        return;
                    }
                    Err(error) => {
                        log::error!(
                            "{}",
                            error.display_chain_with_msg(
                                "Failed to obtain new default route address"
                            )
                        );
                        // Early return
                        return;
                    }
                };

                match address_family {
                    WinNetAddrFamily::IPV4 => {
                        let ip = Ipv4Addr::from(ip);
                        ctx.internet_ipv4 = ip;
                    }
                    WinNetAddrFamily::IPV6 => {
                        let ip = Ipv6Addr::from(ip);
                        ctx.internet_ipv6 = Some(ip);
                    }
                }

                ctx.register_ips()
            }
            // no default route
            winnet::WinNetDefaultRouteChangeEventType::DefaultRouteRemoved => {
                match address_family {
                    WinNetAddrFamily::IPV4 => {
                        ctx.internet_ipv4 = Ipv4Addr::new(0, 0, 0, 0);
                    }
                    WinNetAddrFamily::IPV6 => {
                        ctx.internet_ipv6 = None;
                    }
                }
                ctx.register_ips()
            }
        };

        if let Err(error) = result {
            // TODO: Should we block here?
            log::error!(
                "{}",
                error.display_chain_with_msg(
                    "Failed to register new addresses in split tunnel driver"
                )
            );
        }
    }

    #[cfg(windows)]
    fn update_split_tunnel_addresses(
        &self,
        shared_values: &mut SharedTunnelStateValues,
    ) -> Result<(), BoxedError> {
        // Identify tunnel IP addresses
        // TODO: Multiple IP addresses?
        let mut tunnel_ipv4 = None;
        let mut tunnel_ipv6 = None;

        for ip in &self.metadata.ips {
            match ip {
                IpAddr::V4(address) => tunnel_ipv4 = Some(address.clone()),
                IpAddr::V6(address) => tunnel_ipv6 = Some(address.clone()),
            }
        }

        // Identify IP address that gives us Internet access
        let internet_ipv4 = get_best_default_route(WinNetAddrFamily::IPV4)
            .map_err(BoxedError::new)?
            .map(|route| interface_luid_to_ip(WinNetAddrFamily::IPV4, route.interface_luid))
            .transpose()
            .map_err(BoxedError::new)?
            .flatten();
        let internet_ipv6 = get_best_default_route(WinNetAddrFamily::IPV6)
            .map_err(BoxedError::new)?
            .map(|route| interface_luid_to_ip(WinNetAddrFamily::IPV6, route.interface_luid))
            .transpose()
            .map_err(BoxedError::new)?
            .flatten();

        let tunnel_ipv4 = tunnel_ipv4.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let internet_ipv4 = Ipv4Addr::from(internet_ipv4.unwrap_or_default());
        let internet_ipv6 = internet_ipv6.map(|addr| Ipv6Addr::from(addr));

        let context = SplitTunnelDefaultRouteChangeHandlerContext::new(
            shared_values.split_tunnel.clone(),
            tunnel_ipv4,
            tunnel_ipv6,
            internet_ipv4,
            internet_ipv6,
        );

        shared_values
            .split_tunnel
            .lock()
            .expect("Thread unexpectedly panicked while holding the mutex")
            .register_ips(tunnel_ipv4, tunnel_ipv6, internet_ipv4, internet_ipv6)
            .map_err(BoxedError::new)?;

        #[cfg(target_os = "windows")]
        shared_values.route_manager.add_default_route_callback(
            Some(Self::split_tunnel_default_route_change_handler),
            context,
        );

        Ok(())
    }

    fn set_dns(&self, shared_values: &mut SharedTunnelStateValues) -> Result<(), BoxedError> {
        let mut dns_ips = vec![self.metadata.ipv4_gateway.into()];
        if let Some(ipv6_gateway) = self.metadata.ipv6_gateway {
            dns_ips.push(ipv6_gateway.into());
        };

        shared_values
            .dns_monitor
            .set(&self.metadata.interface, &dns_ips)
            .map_err(BoxedError::new)?;

        #[cfg(target_os = "linux")]
        shared_values
            .route_manager
            .route_exclusions_dns(&self.metadata.interface, &dns_ips)
            .map_err(BoxedError::new)?;

        Ok(())
    }

    fn reset_dns(shared_values: &mut SharedTunnelStateValues) {
        if let Err(error) = shared_values.dns_monitor.reset() {
            log::error!("{}", error.display_chain_with_msg("Unable to reset DNS"));
        }
    }

    fn reset_routes(shared_values: &mut SharedTunnelStateValues) {
        #[cfg(windows)]
        shared_values.route_manager.clear_default_route_callbacks();
        if let Err(error) = shared_values.route_manager.clear_routes() {
            log::error!("{}", error.display_chain_with_msg("Failed to clear routes"));
        }
    }

    fn apply_split_tunnel_config<T: AsRef<OsStr>>(
        shared_values: &SharedTunnelStateValues,
        paths: &[T],
    ) {
        let split_tunnel = shared_values
            .split_tunnel
            .lock()
            .expect("Thread unexpectedly panicked while holding the mutex");
        if let Err(error) = split_tunnel.set_paths(paths) {
            log::error!(
                "{}",
                error.display_chain_with_msg("Failed to apply split tunnel configuration")
            );
        }
    }

    fn disconnect(
        self,
        shared_values: &mut SharedTunnelStateValues,
        after_disconnect: AfterDisconnect,
    ) -> EventConsequence<Self> {
        Self::reset_dns(shared_values);
        Self::reset_routes(shared_values);

        EventConsequence::NewState(DisconnectingState::enter(
            shared_values,
            (self.close_handle, self.tunnel_close_event, after_disconnect),
        ))
    }

    fn handle_commands(
        self,
        commands: &mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence<Self> {
        use self::EventConsequence::*;

        match try_handle_event!(self, commands.poll()) {
            Ok(TunnelCommand::AllowLan(allow_lan)) => {
                if let Err(error_cause) = shared_values.set_allow_lan(allow_lan) {
                    self.disconnect(shared_values, AfterDisconnect::Block(error_cause))
                } else {
                    match self.set_firewall_policy(shared_values) {
                        Ok(()) => SameState(self),
                        Err(error) => self.disconnect(
                            shared_values,
                            AfterDisconnect::Block(ErrorStateCause::SetFirewallPolicyError(error)),
                        ),
                    }
                }
            }
            Ok(TunnelCommand::BlockWhenDisconnected(block_when_disconnected)) => {
                shared_values.block_when_disconnected = block_when_disconnected;
                SameState(self)
            }
            Ok(TunnelCommand::IsOffline(is_offline)) => {
                shared_values.is_offline = is_offline;
                if is_offline {
                    self.disconnect(
                        shared_values,
                        AfterDisconnect::Block(ErrorStateCause::IsOffline),
                    )
                } else {
                    SameState(self)
                }
            }
            Ok(TunnelCommand::Connect) => {
                self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
            }
            Ok(TunnelCommand::Disconnect) | Err(_) => {
                self.disconnect(shared_values, AfterDisconnect::Nothing)
            }
            Ok(TunnelCommand::Block(reason)) => {
                self.disconnect(shared_values, AfterDisconnect::Block(reason))
            }
            #[cfg(windows)]
            Ok(TunnelCommand::SetExcludedApps(paths)) => {
                Self::apply_split_tunnel_config(shared_values, &paths);
                SameState(self)
            }
        }
    }

    fn handle_tunnel_events(
        mut self,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence<Self> {
        use self::EventConsequence::*;

        match try_handle_event!(self, self.tunnel_events.poll()) {
            Ok(TunnelEvent::Down) | Err(_) => {
                self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
            }
            Ok(_) => SameState(self),
        }
    }

    fn handle_tunnel_close_event(
        mut self,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence<Self> {
        use self::EventConsequence::*;

        let poll_result = match &mut self.tunnel_close_event {
            Some(tunnel_close_event) => tunnel_close_event.poll(),
            None => Ok(Async::NotReady),
        };

        match poll_result {
            Ok(Async::Ready(block_reason)) => {
                if let Some(reason) = block_reason {
                    Self::reset_routes(shared_values);
                    return NewState(ErrorState::enter(shared_values, reason));
                }
            }
            Ok(Async::NotReady) => return NoEvents(self),
            Err(_cancelled) => log::warn!("Tunnel monitor thread has stopped unexpectedly"),
        }

        log::info!("Tunnel closed. Reconnecting.");
        Self::reset_dns(shared_values);
        Self::reset_routes(shared_values);
        NewState(ConnectingState::enter(shared_values, 0))
    }
}

impl TunnelState for ConnectedState {
    type Bootstrap = ConnectedStateBootstrap;

    #[cfg_attr(target_os = "android", allow(unused_variables))]
    fn enter(
        shared_values: &mut SharedTunnelStateValues,
        bootstrap: Self::Bootstrap,
    ) -> (TunnelStateWrapper, TunnelStateTransition) {
        let connected_state = ConnectedState::from(bootstrap);
        let tunnel_endpoint = connected_state.tunnel_parameters.get_tunnel_endpoint();

        if let Err(error) = connected_state.set_firewall_policy(shared_values) {
            DisconnectingState::enter(
                shared_values,
                (
                    connected_state.close_handle,
                    connected_state.tunnel_close_event,
                    AfterDisconnect::Block(ErrorStateCause::SetFirewallPolicyError(error)),
                ),
            )
        } else if let Err(error) = connected_state.set_dns(shared_values) {
            log::error!("{}", error.display_chain_with_msg("Failed to set DNS"));
            DisconnectingState::enter(
                shared_values,
                (
                    connected_state.close_handle,
                    connected_state.tunnel_close_event,
                    AfterDisconnect::Block(ErrorStateCause::SetDnsError),
                ),
            )
        } else {
            #[cfg(windows)]
            if let Err(error) = connected_state.update_split_tunnel_addresses(shared_values) {
                log::error!("{}", error.display_chain());
                return DisconnectingState::enter(
                    shared_values,
                    (
                        connected_state.close_handle,
                        connected_state.tunnel_close_event,
                        AfterDisconnect::Block(ErrorStateCause::StartTunnelError),
                    ),
                );
            }

            (
                TunnelStateWrapper::from(connected_state),
                TunnelStateTransition::Connected(tunnel_endpoint),
            )
        }
    }

    fn handle_event(
        self,
        commands: &mut mpsc::UnboundedReceiver<TunnelCommand>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence<Self> {
        self.handle_commands(commands, shared_values)
            .or_else(Self::handle_tunnel_events, shared_values)
            .or_else(Self::handle_tunnel_close_event, shared_values)
    }
}

#[cfg(target_os = "windows")]
struct SplitTunnelDefaultRouteChangeHandlerContext {
    split_tunnel: Arc<Mutex<SplitTunnel>>,
    pub tunnel_ipv4: Ipv4Addr,
    pub tunnel_ipv6: Option<Ipv6Addr>,
    pub internet_ipv4: Ipv4Addr,
    pub internet_ipv6: Option<Ipv6Addr>,
}

#[cfg(target_os = "windows")]
impl SplitTunnelDefaultRouteChangeHandlerContext {
    pub fn new(
        split_tunnel: Arc<Mutex<SplitTunnel>>,
        tunnel_ipv4: Ipv4Addr,
        tunnel_ipv6: Option<Ipv6Addr>,
        internet_ipv4: Ipv4Addr,
        internet_ipv6: Option<Ipv6Addr>,
    ) -> Self {
        SplitTunnelDefaultRouteChangeHandlerContext {
            split_tunnel,
            tunnel_ipv4,
            tunnel_ipv6,
            internet_ipv4,
            internet_ipv6,
        }
    }

    pub fn register_ips(&self) -> Result<(), split_tunnel::Error> {
        let split_tunnel = self
            .split_tunnel
            .lock()
            .expect("Thread unexpectedly panicked while holding the mutex");
        split_tunnel.register_ips(
            self.tunnel_ipv4,
            self.tunnel_ipv6,
            self.internet_ipv4,
            self.internet_ipv6,
        )
    }
}
