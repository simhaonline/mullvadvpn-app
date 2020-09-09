mod driver;
mod windows;

use std::{
    ffi::OsStr,
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Errors that may occur in [`SplitTunnel`].
#[derive(err_derive::Error, Debug)]
#[error(no_from)]
pub enum Error {
    /// Failed to identify or initialize the driver
    #[error(display = "Failed to initialize split tunneling")]
    InitializationFailed(#[error(source)] io::Error),

    /// Failed to set paths to excluded applications
    #[error(display = "Failed to set list of excluded applications")]
    SetConfiguration(#[error(source)] io::Error),

    /// Failed to register interface IP addresses
    #[error(display = "Failed to register IP addresses for exclusions")]
    RegisterIps(#[error(source)] io::Error),
}

/// Manages applications whose traffic to exclude from the tunnel.
pub struct SplitTunnel(driver::DeviceHandle);

impl SplitTunnel {
    /// Initialize the driver.
    pub fn new() -> Result<Self, Error> {
        Ok(SplitTunnel(
            driver::DeviceHandle::new().map_err(Error::InitializationFailed)?,
        ))
    }

    /// Set a list of applications to exclude from the tunnel.
    pub fn set_paths<T: AsRef<OsStr>>(&mut self, paths: &[T]) -> Result<(), Error> {
        self.0.set_config(paths).map_err(Error::SetConfiguration)
    }

    /// Configures IP addresses used for socket rebinding.
    pub fn register_ips(
        &self,
        tunnel_ipv4: Ipv4Addr,
        tunnel_ipv6: Option<Ipv6Addr>,
        internet_ipv4: Ipv4Addr,
        internet_ipv6: Option<Ipv6Addr>,
    ) -> Result<(), Error> {
        self.0
            .register_ips(tunnel_ipv4, tunnel_ipv6, internet_ipv4, internet_ipv6)
            .map_err(Error::RegisterIps)
    }
}
