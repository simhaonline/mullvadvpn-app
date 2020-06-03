use crate::logging::windows::log_sink;
use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

/// Errors that may occur in [`SplitTunnel`].
#[derive(err_derive::Error, Debug)]
pub enum Error {
    /// The Windows DLL or kernel-mode driver returned an error.
    #[error(display = "Failed to initialize split tunneling")]
    InitializationFailed,
}

/// Manages applications whose traffic to exclude from the tunnel.
pub struct SplitTunnel(());

impl SplitTunnel {
    /// Initialize the driver.
    pub fn new() -> Result<Self, Error> {
        // TODO
        Ok(SplitTunnel(()))
    }

    /// Set a list of applications to exclude from the tunnel.
    pub fn set_paths<T: AsRef<OsStr>>(&mut self, paths: &[T]) -> Result<(), Error> {
        // TODO
        Ok(())
    }
}

impl Drop for SplitTunnel {
    fn drop(&mut self) {
        // TODO: Deinitialize driver here
    }
}
