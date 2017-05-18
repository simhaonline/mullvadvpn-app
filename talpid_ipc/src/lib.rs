#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

extern crate serde;
#[macro_use]
extern crate serde_json;

extern crate jsonrpc_core;
extern crate jsonrpc_ws_server;
extern crate ws;
extern crate url;

use jsonrpc_core::{MetaIoHandler, Metadata};
use jsonrpc_ws_server::{MetaExtractor, NoopExtractor, Server, ServerBuilder};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};


#[cfg(windows)]
#[path = "nop_ipc.rs"]
mod ipc_impl;

#[cfg(not(windows))]
#[path = "zmq_ipc.rs"]
mod ipc_impl;

pub use self::ipc_impl::*;

mod client;
pub use client::*;

/// An Id created by the Ipc server that the client can use to connect to it
pub type IpcServerId = String;

error_chain!{
    errors {
        ReadFailure {
            description("Could not read IPC message")
        }
        ParseFailure {
            description("Unable to serialize/deserialize message")
        }
        CouldNotStartServer {
            description("Failed to start the IPC server")
        }
        SendError {
            description("Unable to send message")
        }
        IpcServerError {
            description("Error in IPC server")
        }
    }
}


pub struct IpcServer {
    address: String,
    server: Server,
}

impl IpcServer {
    pub fn start<M: Metadata>(handler: MetaIoHandler<M>) -> Result<Self> {
        Self::start_with_metadata(handler, NoopExtractor)
    }

    pub fn start_with_metadata<M, E>(handler: MetaIoHandler<M>, meta_extractor: E) -> Result<Self>
        where M: Metadata,
              E: MetaExtractor<M>
    {
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        ServerBuilder::new(handler)
            .session_meta_extractor(meta_extractor)
            .start(&listen_addr)
            .map(
                |server| {
                    IpcServer {
                        address: format!("ws://{}", server.addr()),
                        server: server,
                    }
                },
            )
            .chain_err(|| ErrorKind::IpcServerError)
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// Consumes the server, stops it and waits for it to finish.
    pub fn stop(self) {
        self.server.close();
    }

    /// Consumes the server and waits for it to finish.
    pub fn wait(self) -> Result<()> {
        self.server.wait().chain_err(|| ErrorKind::IpcServerError)
    }
}
