use crate::{format, new_rpc_client, state, Command, Result};
use mullvad_management_interface::types::{
    tunnel_state::{
        Error as TunnelError,
        State::{Connected, Disconnected, Error},
    },
    ErrorState,
};
use talpid_types::ErrorExt;

pub struct Reconnect;

#[mullvad_management_interface::async_trait]
impl Command for Reconnect {
    fn name(&self) -> &'static str {
        "reconnect"
    }

    fn clap_subcommand(&self) -> clap::App<'static, 'static> {
        clap::SubCommand::with_name(self.name())
            .about("Command the client to reconnect")
            .arg(
                clap::Arg::with_name("wait")
                    .long("wait")
                    .short("w")
                    .help("Wait until reconnected before exiting"),
            )
    }

    async fn run(&self, matches: &clap::ArgMatches<'_>) -> Result<()> {
        let mut rpc = new_rpc_client().await?;

        let status_listen_handle = if matches.is_present("wait") {
            let state = rpc.get_tunnel_state(()).await?.into_inner();
            format::print_state(&state);

            match state.state {
                Some(Disconnected(_)) => None,
                Some(Error(TunnelError {
                    error_state:
                        Some(ErrorState {
                            blocking_error: Some(_),
                            ..
                        }),
                })) => None,
                _ => Some(
                    state::state_listen(&mut rpc, |state| match state {
                        Connected(_) => false,
                        Error(_) => false,
                        _ => true,
                    })
                    .await?,
                ),
            }
        } else {
            None
        };

        if let Err(e) = rpc.reconnect_tunnel(()).await {
            eprintln!("{}", e.display_chain());
        }
        if let Some(handle) = status_listen_handle {
            handle.await.expect("Failed to listen to status updates");
        }

        Ok(())
    }
}
