//! Linux named TUN and Android/Linux owned FD adapters. No routes or DNS are changed.
#[cfg(target_os = "linux")]
use crate::packet::PacketDeviceFactory;
use crate::packet::{PacketDevice, PacketRecv, PacketSend};
#[cfg(target_os = "linux")]
use std::{ffi::CString, fs::OpenOptions, os::unix::fs::OpenOptionsExt};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::unix::AsyncFd;

pub struct Tun(Arc<AsyncFd<File>>);

impl Tun {
    /// Takes ownership of an already established raw-IP TUN FD, without packet-info headers.
    /// FD must be nonblocking. Duplicate an application-owned FD before passing it here.
    pub fn from_owned_fd(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: fd is live and F_GETFL requires no third argument.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN FD must be nonblocking",
            ));
        }
        Ok(Self(Arc::new(AsyncFd::new(File::from(fd))?)))
    }

    /// Attach to a prepared persistent TUN. Refuses implicit interface creation.
    #[cfg(target_os = "linux")]
    pub fn open(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN name",
            ));
        }
        let name =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: name is NUL-terminated.
        if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "prepare TUN interface before starting VPN",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        // SAFETY: zero is a valid initialization for Linux ifreq.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dest, source) in req.ifr_name.iter_mut().zip(name.as_bytes()) {
            *dest = *source as libc::c_char;
        }
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        // SAFETY: file and req are live for the ioctl.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &req) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_owned_fd(file.into())
    }

    pub fn into_device(self) -> PacketDevice {
        PacketDevice::new(TunRecv(self.0.clone()), TunSend(self.0))
    }
}

struct TunRecv(Arc<AsyncFd<File>>);
struct TunSend(Arc<AsyncFd<File>>);

impl PacketRecv for TunRecv {
    fn poll_recv(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut ready = std::task::ready!(self.0.poll_read_ready(cx))?;
            match ready.try_io(|fd| fd.get_ref().read(buffer)) {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }
    fn try_recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self.0.get_ref().read(buffer) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl PacketSend for TunSend {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        loop {
            let mut ready = std::task::ready!(self.0.poll_write_ready(cx))?;
            match ready.try_io(|fd| fd.get_ref().write(packet)) {
                Ok(Ok(n)) if n == packet.len() => return Poll::Ready(Ok(())),
                Ok(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial TUN packet write",
                    )));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_) => continue,
            }
        }
    }
}

/// Opens an existing interface for each exclusive static-peer server session.
#[cfg(target_os = "linux")]
pub struct NamedTun(pub String);

#[cfg(target_os = "linux")]
impl PacketDeviceFactory for NamedTun {
    fn open(&self) -> io::Result<PacketDevice> {
        Tun::open(&self.0).map(Tun::into_device)
    }
}
