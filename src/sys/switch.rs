use std::cmp::min;
use std::io::IoSlice;
use std::marker::PhantomData;
use std::mem::{self, size_of, MaybeUninit};
use std::net::Shutdown;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::os::switch::io::RawFd;
use std::os::switch::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::time::{Duration, Instant};
use std::{io, slice};
use libc::ssize_t;

use libc::{c_void, in6_addr, in_addr};

use crate::RecvFlags;
use crate::{Domain, SockAddr, TcpKeepalive, Type};

pub(crate) use libc::c_int;

// Used in `Domain`.
pub(crate) use libc::{AF_INET, AF_INET6};
pub(crate) use libc::{SOCK_DGRAM, SOCK_STREAM};
// Used in `Protocol`.
pub(crate) use libc::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
// Used in `SockAddr`.
pub(crate) use libc::{
    sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t,
};
pub(crate) use libc::{MSG_TRUNC, SO_OOBINLINE};
pub(crate) use libc::IP_RECVTOS;
pub(crate) use libc::IP_TOS;
pub(crate) use libc::SO_LINGER;
pub(crate) use libc::{
    ip_mreq as IpMreq, ipv6_mreq as Ipv6Mreq, linger, IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_IF, IPV6_MULTICAST_LOOP, IPV6_UNICAST_HOPS, IPV6_V6ONLY,
    IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP, IP_MULTICAST_IF, IP_MULTICAST_LOOP, IP_MULTICAST_TTL,
    IP_TTL, MSG_OOB, MSG_PEEK, SOL_SOCKET, SO_BROADCAST, SO_ERROR, SO_KEEPALIVE, SO_RCVBUF,
    SO_RCVTIMEO, SO_REUSEADDR, SO_SNDBUF, SO_SNDTIMEO, SO_TYPE, TCP_NODELAY,
};
pub(crate) use libc::{IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP};

pub(crate) type Bool = c_int;

/// Helper macro to execute a system call that returns an `io::Result`.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

const MAX_BUF_LEN: usize = ssize_t::MAX as usize;

type IovLen = usize;

impl_debug!(
    Domain,
    libc::AF_INET,
    libc::AF_INET6,
);

impl_debug!(
    Type,
    libc::SOCK_STREAM,
    libc::SOCK_DGRAM,
    libc::SOCK_RAW,
    libc::SOCK_RDM,
    libc::SOCK_SEQPACKET,
);

#[repr(transparent)]
pub struct MaybeUninitSlice<'a> {
    vec: libc::iovec,
    _lifetime: PhantomData<&'a mut [MaybeUninit<u8>]>,
}

unsafe impl<'a> Send for MaybeUninitSlice<'a> {}

unsafe impl<'a> Sync for MaybeUninitSlice<'a> {}

impl<'a> MaybeUninitSlice<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> MaybeUninitSlice<'a> {
        MaybeUninitSlice {
            vec: libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
            _lifetime: PhantomData,
        }
    }

    pub(crate) fn as_slice(&self) -> &[MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts(self.vec.iov_base.cast(), self.vec.iov_len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts_mut(self.vec.iov_base.cast(), self.vec.iov_len) }
    }
}

pub(crate) type Socket = c_int;

pub(crate) unsafe fn socket_from_raw(socket: Socket) -> crate::socket::Inner {
    crate::socket::Inner::from_raw_fd(socket)
}

pub(crate) fn socket_as_raw(socket: &crate::socket::Inner) -> Socket {
    socket.as_raw_fd()
}

pub(crate) fn socket_into_raw(socket: crate::socket::Inner) -> Socket {
    socket.into_raw_fd()
}

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<Socket> {
    Ok(libc::socket(family, ty, protocol))
}

pub(crate) fn bind(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    Ok(libc::bind(fd, addr.as_ptr(), addr.len() as _)).map(|_| ())
}

pub(crate) fn connect(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    Ok(libc::connect(fd, addr.as_ptr(), addr.len())).map(|_| ())
}

pub(crate) fn poll_connect(socket: &crate::Socket, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();

    let mut pollfd = libc::pollfd {
        fd: socket.as_raw(),
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0,
    };

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(io::ErrorKind::TimedOut.into());
        }

        let timeout = (timeout - elapsed).as_millis();
        let timeout = timeout.clamp(1, c_int::MAX as u128) as c_int;

        match syscall!(poll(&mut pollfd, 1, timeout)) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => {
                // Error or hang up indicates an error (or failure to connect).
                if (pollfd.revents & libc::POLLHUP) != 0 || (pollfd.revents & libc::POLLERR) != 0 {
                    match socket.take_error() {
                        Ok(Some(err)) => return Err(err),
                        Ok(None) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "no error set after POLLHUP",
                            ))
                        }
                        Err(err) => return Err(err),
                    }
                }
                return Ok(());
            }
            // Got interrupted, try again.
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

pub(crate) fn listen(fd: Socket, backlog: c_int) -> io::Result<()> {
    Ok(listen(fd, backlog)).map(|_| ())
}

pub(crate) fn accept(fd: Socket) -> io::Result<(Socket, SockAddr)> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| Ok(libc::accept(fd, storage.cast(), len))) }
}

pub(crate) fn getsockname(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| Ok(libc::getsockname(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn getpeername(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| Ok(libc::getpeername(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn try_clone(fd: Socket) -> io::Result<Socket> {
    Ok(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0))
}

pub(crate) fn set_nonblocking(fd: Socket, nonblocking: bool) -> io::Result<()> {
    if nonblocking {
        fcntl_add(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    } else {
        fcntl_remove(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    }
}

pub(crate) fn shutdown(fd: Socket, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Write => libc::SHUT_WR,
        Shutdown::Read => libc::SHUT_RD,
        Shutdown::Both => libc::SHUT_RDWR,
    };
    Ok(libc::shutdown(fd, how)).map(|_| ())
}

pub(crate) fn recv(fd: Socket, buf: &mut [MaybeUninit<u8>], flags: c_int) -> io::Result<usize> {
    Ok(libc::recv(
        fd,
        buf.as_mut_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ) as usize)
}

pub(crate) fn recv_from(
    fd: Socket,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    // Safety: `recvfrom` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|addr, addrlen| {
            Ok(libc::recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                min(buf.len(), MAX_BUF_LEN),
                flags,
                addr.cast(),
                addrlen
            ))
            .map(|n| n as usize)
        })
    }
}

pub(crate) fn recv_vectored(
    fd: Socket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags)> {
    recvmsg(fd, ptr::null_mut(), bufs, flags).map(|(n, _, recv_flags)| (n, recv_flags))
}

pub(crate) fn recv_from_vectored(
    fd: Socket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags, SockAddr)> {
    // Safety: `recvmsg` initialises the address storage and we set the length
    // manually.
    unsafe {
        SockAddr::init(|storage, len| {
            recvmsg(fd, storage, bufs, flags).map(|(n, addrlen, recv_flags)| {
                // Set the correct address length.
                *len = addrlen;
                (n, recv_flags)
            })
        })
    }
    .map(|((n, recv_flags), addr)| (n, recv_flags, addr))
}

fn recvmsg(
    fd: Socket,
    msg_name: *mut sockaddr_storage,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, libc::socklen_t, RecvFlags)> {
    let msg_namelen = if msg_name.is_null() {
        0
    } else {
        size_of::<sockaddr_storage>() as libc::socklen_t
    };
    // libc::msghdr contains unexported padding fields on Fuchsia.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = msg_name.cast();
    msg.msg_namelen = msg_namelen;
    msg.msg_iov = bufs.as_mut_ptr().cast();
    msg.msg_iovlen = min(bufs.len(), IovLen::MAX as usize) as IovLen;
    Ok((libc::recvmsg(fd, &mut msg, flags) as usize, msg.msg_namelen, RecvFlags(msg.msg_flags)))
}

pub(crate) fn send(fd: Socket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    Ok(libc::send(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ) as usize)
}

pub(crate) fn send_vectored(fd: Socket, bufs: &[IoSlice<'_>], flags: c_int) -> io::Result<usize> {
    sendmsg(fd, ptr::null(), 0, bufs, flags)
}

pub(crate) fn send_to(fd: Socket, buf: &[u8], addr: &SockAddr, flags: c_int) -> io::Result<usize> {
    Ok(libc::sendto(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
        addr.as_ptr(),
        addr.len(),
    ))
    .map(|n| n as usize)
}

pub(crate) fn send_to_vectored(
    fd: Socket,
    bufs: &[IoSlice<'_>],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    sendmsg(fd, addr.as_storage_ptr(), addr.len(), bufs, flags)
}

fn sendmsg(
    fd: Socket,
    msg_name: *const sockaddr_storage,
    msg_namelen: socklen_t,
    bufs: &[IoSlice<'_>],
    flags: c_int,
) -> io::Result<usize> {
    // libc::msghdr contains unexported padding fields on Fuchsia.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    // Safety: we're creating a `*mut` pointer from a reference, which is UB
    // once actually used. However the OS should not write to it in the
    // `sendmsg` system call.
    msg.msg_name = (msg_name as *mut sockaddr_storage).cast();
    msg.msg_namelen = msg_namelen;
    // Safety: Same as above about `*const` -> `*mut`.
    msg.msg_iov = bufs.as_ptr() as *mut _;
    msg.msg_iovlen = min(bufs.len(), IovLen::MAX as usize) as IovLen;
    Ok(libc::sendmsg(fd, &msg, flags) as usize)
}

/// Wrapper around `setsockopt` to deal with platform specific timeouts.
pub(crate) fn set_timeout_opt(
    fd: Socket,
    opt: c_int,
    val: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let duration = into_timeval(duration);
    unsafe { setsockopt(fd, opt, val, duration) }
}

fn into_timeval(duration: Option<Duration>) -> libc::timeval {
    match duration {
        // https://github.com/rust-lang/libc/issues/1848
        #[cfg_attr(target_env = "musl", allow(deprecated))]
        Some(duration) => libc::timeval {
            tv_sec: min(duration.as_secs(), libc::time_t::MAX as u64) as libc::time_t,
            tv_usec: duration.subsec_micros() as libc::suseconds_t,
        },
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    }
}

/// Add `flag` to the current set flags of `F_GETFD`.
fn fcntl_add(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = libc::fcntl(fd, get_cmd);
    let new = previous | flag;
    if new != previous {
        Ok(libc::fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Remove `flag` to the current set flags of `F_GETFD`.
fn fcntl_remove(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = libc::fcntl(fd, get_cmd);
    let new = previous & !flag;
    if new != previous {
        Ok(libc::fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn getsockopt<T>(fd: Socket, opt: c_int, val: c_int) -> io::Result<T> {
    let mut payload: MaybeUninit<T> = MaybeUninit::uninit();
    let mut len = size_of::<T>() as libc::socklen_t;
    Ok(libc::getsockopt(
        fd,
        opt,
        val,
        payload.as_mut_ptr().cast(),
        &mut len,
    ))
    .map(|_| {
        debug_assert_eq!(len as usize, size_of::<T>());
        // Safety: `getsockopt` initialised `payload` for us.
        payload.assume_init()
    })
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn setsockopt<T>(
    fd: Socket,
    opt: c_int,
    val: c_int,
    payload: T,
) -> io::Result<()> {
    let payload = &payload as *const T as *const c_void;
    Ok(libc::setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as libc::socklen_t,
    ))
    .map(|_| ())
}

pub(crate) fn timeout_opt(fd: Socket, opt: c_int, val: c_int) -> io::Result<Option<Duration>> {
    unsafe { getsockopt(fd, opt, val).map(from_timeval) }
}

fn from_timeval(duration: libc::timeval) -> Option<Duration> {
    if duration.tv_sec == 0 && duration.tv_usec == 0 {
        None
    } else {
        let sec = duration.tv_sec as u64;
        let nsec = (duration.tv_usec as u32) * 1000;
        Some(Duration::new(sec, nsec))
    }
}

#[allow(unused_variables)]
pub(crate) fn set_tcp_keepalive(fd: Socket, keepalive: &TcpKeepalive) -> io::Result<()> {
    if let Some(interval) = keepalive.interval {
        let secs = into_secs(interval);
        unsafe { setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, secs)? }
    }

    if let Some(retries) = keepalive.retries {
        unsafe { setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, retries as c_int)? }
    }

    Ok(())
}

fn into_secs(duration: Duration) -> c_int {
    min(duration.as_secs(), c_int::MAX as u64) as c_int
}

pub(crate) fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
    // `s_addr` is stored as BE on all machines, and the array is in BE order.
    // So the native endian conversion method is used so that it's never
    // swapped.
    in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(in_addr: in_addr) -> Ipv4Addr {
    Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())
}

pub(crate) fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    in6_addr {
        s6_addr: addr.octets(),
    }
}

pub(crate) fn from_in6_addr(addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

impl AsRawFd for crate::Socket {
    fn as_raw_fd(&self) -> c_int {
        self.as_raw()
    }
}

impl IntoRawFd for crate::Socket {
    fn into_raw_fd(self) -> c_int {
        self.into_raw()
    }
}

impl FromRawFd for crate::Socket {
    unsafe fn from_raw_fd(fd: c_int) -> crate::Socket {
        crate::Socket::from_raw(fd)
    }
}

#[cfg(feature = "all")]
from!(Socket, crate::Socket);
#[cfg(feature = "all")]
from!(TcpListener, crate::Socket);
#[cfg(feature = "all")]
from!(crate::Socket, Socket);
#[cfg(feature = "all")]
from!(crate::Socket, TcpListener);