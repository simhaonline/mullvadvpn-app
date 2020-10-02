use super::{
    AfterDisconnect, ConnectingState, DisconnectingState, ErrorState, EventConsequence,
    SharedTunnelStateValues, TunnelCommand, TunnelCommandReceiver, TunnelState,
    TunnelStateTransition, TunnelStateWrapper,
};
use crate::{
    firewall::FirewallPolicy,
    tunnel::{CloseHandle, TunnelEvent, TunnelMetadata},
};
use futures::{stream::FusedStream, StreamExt};
use std::pin::Pin;
use talpid_types::{
    net::TunnelParameters,
    tunnel::{ErrorStateCause, FirewallPolicyError},
    BoxedError, ErrorExt,
};

#[cfg(windows)]
use crate::tunnel::TunnelMonitor;

use super::connecting_state::TunnelCloseEvent;

pub(crate) type TunnelEventsReceiver = Pin<Box<dyn FusedStream<Item = TunnelEvent> + Send>>;


pub struct ConnectedStateBootstrap {
    pub metadata: TunnelMetadata,
    pub tunnel_events: TunnelEventsReceiver,
    pub tunnel_parameters: TunnelParameters,
    pub tunnel_close_event: TunnelCloseEvent,
    pub close_handle: Option<CloseHandle>,
}

/// The tunnel is up and working.
pub struct ConnectedState {
    metadata: TunnelMetadata,
    tunnel_events: TunnelEventsReceiver,
    tunnel_parameters: TunnelParameters,
    tunnel_close_event: TunnelCloseEvent,
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

    fn disconnect(
        self,
        shared_values: &mut SharedTunnelStateValues,
        after_disconnect: AfterDisconnect,
    ) -> EventConsequence {
        Self::reset_dns(shared_values);
        Self::reset_routes(shared_values);

        EventConsequence::NewState(DisconnectingState::enter(
            shared_values,
            (self.close_handle, self.tunnel_close_event, after_disconnect),
        ))
    }

    fn handle_commands(
        self,
        command: Option<TunnelCommand>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        use self::EventConsequence::*;

        match command {
            Some(TunnelCommand::AllowLan(allow_lan)) => {
                if let Err(error_cause) = shared_values.set_allow_lan(allow_lan) {
                    self.disconnect(shared_values, AfterDisconnect::Block(error_cause))
                } else {
                    match self.set_firewall_policy(shared_values) {
                        Ok(()) => SameState(self.into()),
                        Err(error) => self.disconnect(
                            shared_values,
                            AfterDisconnect::Block(ErrorStateCause::SetFirewallPolicyError(error)),
                        ),
                    }
                }
            }
            Some(TunnelCommand::BlockWhenDisconnected(block_when_disconnected)) => {
                shared_values.block_when_disconnected = block_when_disconnected;
                SameState(self.into())
            }
            Some(TunnelCommand::IsOffline(is_offline)) => {
                shared_values.is_offline = is_offline;
                if is_offline {
                    self.disconnect(
                        shared_values,
                        AfterDisconnect::Block(ErrorStateCause::IsOffline),
                    )
                } else {
                    SameState(self.into())
                }
            }
            Some(TunnelCommand::Connect) => {
                self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
            }
            Some(TunnelCommand::Disconnect) | None => {
                self.disconnect(shared_values, AfterDisconnect::Nothing)
            }
            Some(TunnelCommand::Block(reason)) => {
                self.disconnect(shared_values, AfterDisconnect::Block(reason))
            }
        }
    }

    fn handle_tunnel_events(
        self,
        event: Option<TunnelEvent>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        use self::EventConsequence::*;

        match event {
            Some(TunnelEvent::Down) | None => {
                self.disconnect(shared_values, AfterDisconnect::Reconnect(0))
            }
            Some(_) => SameState(self.into()),
        }
    }

    fn handle_tunnel_close_event(
        self,
        block_reason: Option<ErrorStateCause>,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        use self::EventConsequence::*;

        if let Some(block_reason) = block_reason {
            Self::reset_routes(shared_values);
            return NewState(ErrorState::enter(shared_values, block_reason));
        }

        log::info!("Tunnel closed. Reconnecting.");
        Self::reset_dns(shared_values);
        Self::reset_routes(shared_values);
        NewState(ConnectingState::enter(shared_values, 0))
    }
}

#[async_trait::async_trait]
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
            (
                TunnelStateWrapper::from(connected_state),
                TunnelStateTransition::Connected(tunnel_endpoint),
            )
        }
    }

    async fn handle_event(
        mut self,
        commands: &mut TunnelCommandReceiver,
        shared_values: &mut SharedTunnelStateValues,
    ) -> EventConsequence {
        return futures::select! {
            command = commands.next() => {
                self.handle_commands(command, shared_values)
            }
            event = self.tunnel_events.next() => {
                self.handle_tunnel_events(event, shared_values)
            }
            result = &mut self.tunnel_close_event => {
                if result.is_err() {
                    log::warn!("Tunnel monitor thread has stopped unexpectedly");
                }
                let block_reason = result.unwrap_or(None);
                self.handle_tunnel_close_event(block_reason, shared_values)
            }
        };
    }
}
