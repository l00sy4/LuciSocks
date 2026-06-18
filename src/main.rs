use sha2::{Digest, Sha256};
use std::{
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tailscale::{Config, Device, netstack};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket, lookup_host},
};

const SOCKS_VERSION: u8 = 0x05;
const USERPASS_VERSION: u8 = 0x01;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

const ATYP_V4: u8 = 0x01;
const ATYP_FQDN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;

const RELAY_BUF: usize = 64 << 10;
const UDP_BUF: usize = 65_535;

type Creds = Option<[u8; 32]>;

enum Entry {
    Os {
        addr: &'static str,
        creds: Creds,
    },
    Tailnet {
        auth_key: &'static str,
        port: u16,
        creds: Creds,
    },
}

const CONFIG: &[Entry] = &[
    Entry::Os {
        addr: "127.0.0.1:1338",
        creds: Some([
            0x05, 0xD4, 0x96, 0x92, 0xB7, 0x55, 0xF9, 0x9C, 0x45, 0x04, 0xB5, 0x10, 0x41, 0x8E,
            0xFE, 0xEE, 0xEB, 0xFD, 0x46, 0x68, 0x92, 0x54, 0x0F, 0x27, 0xAC, 0xF9, 0xA3, 0x1A,
            0x32, 0x6D, 0x65, 0x04,
        ]),
    },
    Entry::Os {
        addr: "127.0.0.25:1330",
        creds: None,
    },
];

fn reply_for_error(e: &std::io::Error) -> u8 {
    match e.kind() {
        ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        ErrorKind::TimedOut | ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
        ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
        _ => REP_GENERAL_FAILURE,
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> Error {
    Error::other(e.to_string())
}

#[derive(Clone)]
enum Net {
    Os,
    Tailnet(Arc<Device>),
}

impl Net {
    async fn tcp_connect(&self, target: SocketAddr) -> std::io::Result<Stream> {
        match self {
            Net::Os => Ok(Stream::Os(TcpStream::connect(target).await?)),
            Net::Tailnet(d) => Ok(Stream::Ts(d.tcp_connect(target).await.map_err(io_err)?)),
        }
    }

    async fn tcp_listen(&self, addr: SocketAddr) -> std::io::Result<Listener> {
        match self {
            Net::Os => Ok(Listener::Os(TcpListener::bind(addr).await?)),
            Net::Tailnet(d) => Ok(Listener::Ts(d.tcp_listen(addr).await.map_err(io_err)?)),
        }
    }

    async fn udp_bind(&self, addr: SocketAddr) -> std::io::Result<Udp> {
        match self {
            Net::Os => Ok(Udp::Os(UdpSocket::bind(addr).await?)),
            Net::Tailnet(d) => Ok(Udp::Ts(d.udp_bind(addr).await.map_err(io_err)?)),
        }
    }

    async fn outbound_addr(&self, v6: bool) -> std::io::Result<SocketAddr> {
        match self {
            Net::Os => Ok(if v6 {
                (Ipv6Addr::UNSPECIFIED, 0).into()
            } else {
                (Ipv4Addr::UNSPECIFIED, 0).into()
            }),
            Net::Tailnet(d) => {
                let ip: IpAddr = if v6 {
                    d.ipv6_addr().await.map_err(io_err)?.into()
                } else {
                    d.ipv4_addr().await.map_err(io_err)?.into()
                };
                Ok((ip, 0).into())
            }
        }
    }
}

enum Stream {
    Os(TcpStream),
    Ts(netstack::TcpStream),
}

impl Stream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Stream::Os(s) => s.local_addr(),
            Stream::Ts(s) => Ok(s.local_addr()),
        }
    }

    fn set_nodelay(&self, on: bool) {
        if let Stream::Os(s) = self {
            let _ = s.set_nodelay(on);
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Os(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Ts(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Os(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Ts(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Os(s) => Pin::new(s).poll_flush(cx),
            Stream::Ts(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Os(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Ts(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

enum Listener {
    Os(TcpListener),
    Ts(netstack::TcpListener),
}

impl Listener {
    async fn accept(&self) -> std::io::Result<(Stream, SocketAddr)> {
        match self {
            Listener::Os(l) => {
                let (s, a) = l.accept().await?;
                Ok((Stream::Os(s), a))
            }
            Listener::Ts(l) => {
                let s = l.accept().await.map_err(io_err)?;
                let peer = s.remote_addr();
                Ok((Stream::Ts(s), peer))
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Listener::Os(l) => l.local_addr(),
            Listener::Ts(l) => Ok(l.local_addr()),
        }
    }
}

enum Udp {
    Os(UdpSocket),
    Ts(netstack::UdpSocket),
}

impl Udp {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self {
            Udp::Os(s) => s.recv_from(buf).await,
            Udp::Ts(s) => s
                .recv_from(buf)
                .await
                .map(|(addr, n)| (n, addr))
                .map_err(io_err),
        }
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        match self {
            Udp::Os(s) => s.send_to(buf, target).await,
            Udp::Ts(s) => s
                .send_to(target, buf)
                .await
                .map(|()| buf.len())
                .map_err(io_err),
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Udp::Os(s) => s.local_addr(),
            Udp::Ts(s) => Ok(s.local_addr()),
        }
    }
}

#[tokio::main]
async fn main() {
    unsafe {
        std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");
    }

    let mut handles = Vec::new();
    for entry in CONFIG {
        match entry {
            Entry::Os { addr, creds } => {
                let addr: SocketAddr = addr.parse().unwrap();
                let creds = *creds;
                handles.push(tokio::spawn(serve_os(addr, creds)));
            }
            Entry::Tailnet {
                auth_key,
                port,
                creds,
            } => {
                let (auth_key, port, creds) = (*auth_key, *port, *creds);
                handles.push(tokio::spawn(serve_tailnet(auth_key, port, creds)));
            }
        }
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn serve_os(addr: SocketAddr, creds: Creds) {
    let Ok(listener) = TcpListener::bind(addr).await else {
        return;
    };

    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                tokio::spawn(async move {
                    let _ = handle_socks5(Stream::Os(socket), Net::Os, creds).await;
                });
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn serve_tailnet(auth_key: &'static str, port: u16, creds: Creds) {
    let Ok(dev) = Device::new(&Config::default(), Some(auth_key.to_string())).await else {
        return;
    };

    let dev = Arc::new(dev);
    let Ok(ip) = dev.ipv4_addr().await else {
        return;
    };
    let Ok(listener) = dev.tcp_listen((ip, port).into()).await else {
        return;
    };

    let net = Net::Tailnet(dev);
    loop {
        match listener.accept().await {
            Ok(socket) => {
                let net = net.clone();
                tokio::spawn(async move {
                    let _ = handle_socks5(Stream::Ts(socket), net, creds).await;
                });
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn send_socks_reply(socket: &mut Stream, rep: u8, bound: SocketAddr) -> std::io::Result<()> {
    let mut msg = vec![SOCKS_VERSION, rep, 0x00];
    match bound.ip() {
        IpAddr::V4(ip) => {
            msg.push(ATYP_V4);
            msg.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            msg.push(ATYP_V6);
            msg.extend_from_slice(&ip.octets());
        }
    }
    msg.extend_from_slice(&bound.port().to_be_bytes());
    socket.write_all(&msg).await
}

async fn validate_password(socket: &mut Stream, expect: [u8; 32]) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    socket.read_exact(&mut head).await?;
    let [version, ulen] = head;
    if version != USERPASS_VERSION {
        return Err(Error::from(ErrorKind::Unsupported));
    }

    let ulen = ulen as usize;
    let mut user_buf = [0u8; 256];
    let mut pass_buf = [0u8; 255];

    socket.read_exact(&mut user_buf[..=ulen]).await?;
    let plen = user_buf[ulen] as usize;
    socket.read_exact(&mut pass_buf[..plen]).await?;

    let username = &user_buf[..ulen];
    let password = &pass_buf[..plen];

    let mut hasher = Sha256::new();
    hasher.update(username);
    hasher.update(password);
    let digest = hasher.finalize();
    let ok = digest.as_slice() == expect.as_slice();

    socket.write_all(&[USERPASS_VERSION, u8::from(!ok)]).await?;

    if ok {
        Ok(())
    } else {
        Err(Error::from(ErrorKind::PermissionDenied))
    }
}

async fn read_target(socket: &mut Stream, atyp: u8) -> std::io::Result<SocketAddr> {
    match atyp {
        ATYP_V4 => {
            let mut ipv4 = [0u8; 6];
            socket.read_exact(&mut ipv4).await?;
            let [a @ .., p0, p1] = ipv4;
            Ok((Ipv4Addr::from(a), u16::from_be_bytes([p0, p1])).into())
        }
        ATYP_V6 => {
            let mut ipv6 = [0u8; 18];
            socket.read_exact(&mut ipv6).await?;
            let [a @ .., p0, p1] = ipv6;
            Ok((Ipv6Addr::from(a), u16::from_be_bytes([p0, p1])).into())
        }
        ATYP_FQDN => {
            let len = socket.read_u8().await? as usize;
            let mut b = vec![0u8; len + 2];
            socket.read_exact(&mut b).await?;
            let (name, [p0, p1]) = b.split_last_chunk().unwrap();
            let host = String::from_utf8_lossy(name);
            lookup_host((host.as_ref(), u16::from_be_bytes([*p0, *p1])))
                .await?
                .next()
                .ok_or_else(|| Error::from(ErrorKind::HostUnreachable))
        }
        _ => Err(Error::from(ErrorKind::Unsupported)),
    }
}

async fn handle_connect(mut client: Stream, target: SocketAddr, net: Net) -> std::io::Result<()> {
    let mut upstream = match net.tcp_connect(target).await {
        Ok(s) => s,
        Err(e) => {
            send_socks_reply(&mut client, reply_for_error(&e), target).await?;
            return Ok(());
        }
    };

    send_socks_reply(&mut client, REP_SUCCESS, upstream.local_addr()?).await?;

    client.set_nodelay(true);
    upstream.set_nodelay(true);
    tokio::io::copy_bidirectional_with_sizes(&mut client, &mut upstream, RELAY_BUF, RELAY_BUF)
        .await?;
    Ok(())
}

async fn handle_bind(mut client: Stream, expected: IpAddr, net: Net) -> std::io::Result<()> {
    let unspecified = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let listener = match net.tcp_listen((client.local_addr()?.ip(), 0).into()).await {
        Ok(l) => l,
        Err(e) => {
            send_socks_reply(&mut client, reply_for_error(&e), unspecified).await?;
            return Ok(());
        }
    };
    send_socks_reply(&mut client, REP_SUCCESS, listener.local_addr()?).await?;

    let (mut inbound, peer) = loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                send_socks_reply(&mut client, reply_for_error(&e), unspecified).await?;
                return Ok(());
            }
        };
        if expected.is_unspecified() || peer.ip() == expected {
            break (stream, peer);
        }
    };
    send_socks_reply(&mut client, REP_SUCCESS, peer).await?;

    client.set_nodelay(true);
    inbound.set_nodelay(true);
    tokio::io::copy_bidirectional(&mut client, &mut inbound).await?;
    Ok(())
}

enum UdpDest {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl UdpDest {
    async fn resolve(self) -> std::io::Result<SocketAddr> {
        match self {
            UdpDest::Addr(addr) => Ok(addr),
            UdpDest::Domain(host, port) => lookup_host((host.as_str(), port))
                .await?
                .next()
                .ok_or_else(|| Error::from(ErrorKind::HostUnreachable)),
        }
    }
}

fn build_udp_header(src: SocketAddr, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    match src {
        SocketAddr::V4(a) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
}

async fn forward_to_client(
    relay: &Udp,
    client: SocketAddr,
    src: SocketAddr,
    payload: &[u8],
    scratch: &mut Vec<u8>,
) {
    scratch.clear();
    build_udp_header(src, scratch);
    scratch.extend_from_slice(payload);
    let _ = relay.send_to(scratch, client).await;
}

fn accept_client(lock: &mut Option<SocketAddr>, requested: SocketAddr, src: SocketAddr) -> bool {
    if let Some(addr) = *lock {
        addr == src
    } else {
        let ok = requested.ip().is_unspecified() || requested.port() == 0 || requested == src;
        if ok {
            *lock = Some(src);
        }
        ok
    }
}

fn parse_udp_header(buf: &[u8]) -> std::io::Result<(u8, UdpDest, usize)> {
    let short = || Error::from(ErrorKind::InvalidData);
    if buf.len() < 4 {
        return Err(short());
    }
    let frag = buf[2];
    match buf[3] {
        ATYP_V4 => {
            let end = 4 + 4 + 2;
            if buf.len() < end {
                return Err(short());
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok((frag, UdpDest::Addr((ip, port).into()), end))
        }
        ATYP_V6 => {
            let end = 4 + 16 + 2;
            if buf.len() < end {
                return Err(short());
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok((frag, UdpDest::Addr((Ipv6Addr::from(o), port).into()), end))
        }
        ATYP_FQDN => {
            if buf.len() < 5 {
                return Err(short());
            }
            let dlen = buf[4] as usize;
            let end = 5 + dlen + 2;
            if buf.len() < end {
                return Err(short());
            }
            let host = std::str::from_utf8(&buf[5..5 + dlen])
                .map_err(|_| Error::from(ErrorKind::InvalidData))?
                .to_owned();
            let port = u16::from_be_bytes([buf[end - 2], buf[end - 1]]);
            Ok((frag, UdpDest::Domain(host, port), end))
        }
        _ => Err(Error::from(ErrorKind::InvalidData)),
    }
}

async fn handle_udp_associate(
    mut control: Stream,
    requested: SocketAddr,
    net: Net,
) -> std::io::Result<()> {
    let relay = net.udp_bind((control.local_addr()?.ip(), 0).into()).await?;
    send_socks_reply(&mut control, REP_SUCCESS, relay.local_addr()?).await?;

    let out4 = net.udp_bind(net.outbound_addr(false).await?).await?;
    let out6 = net.udp_bind(net.outbound_addr(true).await?).await?;

    let mut client: Option<SocketAddr> = None;
    let mut scratch = Vec::with_capacity(UDP_BUF);
    let (mut cbuf, mut s4buf, mut s6buf) =
        (vec![0u8; UDP_BUF], vec![0u8; UDP_BUF], vec![0u8; UDP_BUF]);
    let mut ctlbuf = [0u8; 64];

    loop {
        tokio::select! {
            res = relay.recv_from(&mut cbuf) => {
                let (n, src) = res?;
                if !accept_client(&mut client, requested, src) {
                    continue;
                }
                let datagram = &cbuf[..n];
                let (_frag, dest, hdr_len) = match parse_udp_header(datagram) {
                    Ok(v) if v.0 == 0x00 => v,
                    _ => continue,
                };
                let Ok(dest) = dest.resolve().await else { continue };
                let out = if dest.is_ipv4() { &out4 } else { &out6 };
                let _ = out.send_to(&datagram[hdr_len..], dest).await;
            }
            res = out4.recv_from(&mut s4buf) => {
                let (n, src) = res?;
                if let Some(c) = client {
                    forward_to_client(&relay, c, src, &s4buf[..n], &mut scratch).await;
                }
            }
            res = out6.recv_from(&mut s6buf) => {
                let (n, src) = res?;
                if let Some(c) = client {
                    forward_to_client(&relay, c, src, &s6buf[..n], &mut scratch).await;
                }
            }
            res = control.read(&mut ctlbuf) => {
                if matches!(res, Ok(0) | Err(_)) {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_socks5(mut socket: Stream, net: Net, creds: Creds) -> std::io::Result<()> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    let [version, nmethods] = header;
    if version != SOCKS_VERSION {
        return Err(Error::from(ErrorKind::Unsupported));
    }

    let mut methods = [0u8; 255];
    let methods = &mut methods[..nmethods as usize];
    socket.read_exact(methods).await?;

    let chosen = match creds {
        Some(_) if methods.contains(&METHOD_USERPASS) => METHOD_USERPASS,
        None if methods.contains(&METHOD_NO_AUTH) => METHOD_NO_AUTH,
        _ => METHOD_NONE_ACCEPTABLE,
    };

    socket.write_all(&[SOCKS_VERSION, chosen]).await?;

    match chosen {
        METHOD_NO_AUTH => {}
        METHOD_USERPASS => validate_password(&mut socket, creds.unwrap()).await?,
        _ => return Ok(()),
    }

    let mut head = [0u8; 4];
    socket.read_exact(&mut head).await?;
    let [version, cmd, _rsv, atyp] = head;
    if version != SOCKS_VERSION {
        return Err(Error::from(ErrorKind::Unsupported));
    }

    let target: SocketAddr = read_target(&mut socket, atyp).await?;

    match cmd {
        CMD_CONNECT => handle_connect(socket, target, net).await?,
        CMD_BIND => handle_bind(socket, target.ip(), net).await?,
        CMD_UDP_ASSOCIATE => handle_udp_associate(socket, target, net).await?,
        _ => {
            return Err(Error::from(ErrorKind::Unsupported));
        }
    }

    Ok(())
}
