//! Packet boundaries are preserved. Neither interface configures routes or DNS.
use std::{
    io,
    task::{Context, Poll},
};

/// Receives a complete raw IPv4/IPv6 packet, without platform packet-info headers.
/// `buffer` is 65536 bytes in the engine. Return an error rather than silently
/// truncating larger packets. Pending operations must be cancellation-safe.
pub trait PacketRecv: Send + 'static {
    fn poll_recv(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>>;

    /// Optional nonblocking receive, used to batch packets already queued.
    fn try_recv(&mut self, _buffer: &mut [u8]) -> io::Result<Option<usize>> {
        Ok(None)
    }
}

/// Writes one complete packet. Partial writes are errors, never another packet.
/// Polls must return promptly without blocking or re-entering the owning session
/// or router: these may serialize polling with generation changes under a lock.
/// Pending must not consume the packet; cancellation may discard it. Register
/// the supplied waker when Pending so the owner can resume on readiness.
pub trait PacketSend: Send + 'static {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>>;
}

/// Owned endpoints. Dropping both releases the library's ownership of the device.
pub struct PacketDevice {
    pub recv: Box<dyn PacketRecv>,
    pub send: Box<dyn PacketSend>,
}

impl PacketDevice {
    pub fn new(recv: impl PacketRecv, send: impl PacketSend) -> Self {
        Self {
            recv: Box::new(recv),
            send: Box::new(send),
        }
    }
}

/// Server adapter for opening an externally configured single-peer device.
/// The server holds its exclusive session permit until both endpoints are dropped.
pub trait PacketDeviceFactory: Send + Sync + 'static {
    fn open(&self) -> io::Result<PacketDevice>;
}
