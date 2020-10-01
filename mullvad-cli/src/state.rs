use crate::{format, Result};
use mullvad_management_interface::{
    types::{daemon_event::Event as EventType, tunnel_state::State},
    ManagementServiceClient,
};
use tokio::task::JoinHandle;

// Listens to state changes and prints each new state. To stop listening for changes, return false
// in continue_condition.
pub async fn state_listen<C: Fn(&State) -> bool + Send + 'static>(
    rpc: &mut ManagementServiceClient,
    continue_condition: C,
) -> Result<JoinHandle<()>> {
    let mut events = rpc.events_listen(()).await?.into_inner();
    let join_handle = tokio::spawn(async move {
        while let Some(event) = events.message().await.unwrap_or(None) {
            if let EventType::TunnelState(new_state) = event.event.unwrap() {
                format::print_state(&new_state);
                if !continue_condition(&new_state.state.unwrap()) {
                    break;
                }
            }
        }
    });

    Ok(join_handle)
}
