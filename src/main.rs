use std::{
    env,
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, lookup_host},
    sync::Semaphore,
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

const MAX_CLIENTS: usize = 128;
const RELAY_BUF: usize = 64 << 10;
const UDP_BUF: usize = 65_535;

fn reply_for_error(e: &std::io::Error) -> u8 {
    match e.kind() {
        ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        ErrorKind::TimedOut | ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
        ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
        _ => REP_GENERAL_FAILURE,
    }
}

#[tokio::main]
async fn main() {
    let addresses: Vec<SocketAddr> = env::args()
        .skip(1)
        .map(|s| {
            s.parse()
                .expect("Please specify at least one valid IPv4 or IPv6 address")
        })
        .collect();

    let mut handles = Vec::new();
    for addr in addresses {
        let listener = TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to start listening on {addr}: {e}"));

        let semaphore = Arc::new(Semaphore::new(MAX_CLIENTS));
        handles.push(tokio::spawn(async move {
            loop {
                let permit = semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("Semaphore closed");

                match listener.accept().await {
                    Ok((socket, _)) => {
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _ = handle_client(socket).await;
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn send_socks_reply(
    socket: &mut TcpStream,
    rep: u8,
    bound: SocketAddr,
) -> std::io::Result<()> {
    //
    // The server evaluates the request, and
    // returns a reply formed as follows:
    //
    //        +----+-----+-------+------+----------+----------+
    //        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //        +----+-----+-------+------+----------+----------+
    //        | 1  |  1  | X'00' |  1   | Variable |    2     |
    //        +----+-----+-------+------+----------+----------+
    //

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

async fn validate_password(socket: &mut TcpStream) -> std::io::Result<()> {
    //
    // This begins with the client producing a
    // username/password request:
    //
    //           +----+------+----------+------+----------+
    //           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    //           +----+------+----------+------+----------+
    //           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    //           +----+------+----------+------+----------+
    //

    let mut head = [0u8; 2];
    socket.read_exact(&mut head).await?;
    let [version, ulen] = head;

    if version != USERPASS_VERSION {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "Unsupported userpass version",
        ));
    }

    let ulen = ulen as usize;
    let mut user_buf = [0u8; 256];
    let mut pass_buf = [0u8; 255];

    socket.read_exact(&mut user_buf[..=ulen]).await?;
    let plen = user_buf[ulen] as usize;
    socket.read_exact(&mut pass_buf[..plen]).await?;

    let username = &user_buf[..ulen];
    let password = &pass_buf[..plen];
    let ok = username == b"luci4" && password == b"rocks";

    //
    //  The server verifies the supplied UNAME and PASSWD, and sends the
    //  following response:
    //
    //                   +----+--------+
    //                   |VER | STATUS |
    //                   +----+--------+
    //                   | 1  |   1    |
    //                   +----+--------+

    socket.write_all(&[USERPASS_VERSION, u8::from(!ok)]).await?;

    if ok {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "Authentication failed",
        ))
    }
}

async fn read_target(socket: &mut TcpStream, atyp: u8) -> std::io::Result<SocketAddr> {
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
                .ok_or_else(|| Error::other("could not resolve host"))
        }
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            "Unsupported address type",
        )),
    }
}

async fn handle_connect(mut client: TcpStream, target: SocketAddr) -> std::io::Result<()> {
    let mut upstream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            let rep = reply_for_error(&e);
            send_socks_reply(&mut client, rep, target).await?;
            return Ok(());
        }
    };

    //
    //  In the reply to a CONNECT, BND.PORT contains the port number that the
    //  server assigned to connect to the target host, while BND.ADDR
    //  contains the associated IP address
    //

    let bound = upstream.local_addr()?;
    send_socks_reply(&mut client, REP_SUCCESS, bound).await?;

    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    tokio::io::copy_bidirectional_with_sizes(&mut client, &mut upstream, RELAY_BUF, RELAY_BUF)
        .await?;
    Ok(())
}

async fn handle_bind(mut client: TcpStream, expected: IpAddr) -> std::io::Result<()> {
    let unspecified = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    //
    // The first reply is sent after the server creates and binds a new socket
    //

    let listener = match TcpListener::bind((client.local_addr()?.ip(), 0)).await {
        Ok(l) => l,
        Err(e) => {
            send_socks_reply(&mut client, reply_for_error(&e), unspecified).await?;
            return Ok(());
        }
    };

    send_socks_reply(&mut client, REP_SUCCESS, listener.local_addr()?).await?;

    //
    // The second reply occurs only after the anticipated incoming connection
    // succeeds or fails
    //

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

    let _ = client.set_nodelay(true);
    let _ = inbound.set_nodelay(true);
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
                .ok_or_else(|| Error::other("could not resolve UDP destination")),
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
    relay: &UdpSocket,
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
    let short = || Error::new(ErrorKind::InvalidData, "UDP datagram truncated");
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
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Bad domain in UDP header"))?
                .to_owned();
            let port = u16::from_be_bytes([buf[end - 2], buf[end - 1]]);
            Ok((frag, UdpDest::Domain(host, port), end))
        }
        _ => Err(Error::new(ErrorKind::InvalidData, "Bad ATYP in UDP header")),
    }
}

async fn handle_udp_associate(
    mut control: TcpStream,
    requested: SocketAddr,
) -> std::io::Result<()> {
    //
    // Relay socket on the same interface the client reached us on
    //

    let relay = UdpSocket::bind((control.local_addr()?.ip(), 0)).await?;
    send_socks_reply(&mut control, REP_SUCCESS, relay.local_addr()?).await?;

    let out4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let out6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;

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

            //
            //  A UDP association terminates when the TCP connection
            //  that the UDP ASSOCIATE request arrived on terminates
            //

            res = control.read(&mut ctlbuf) => {
                if matches!(res, Ok(0) | Err(_)) {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_client(mut socket: TcpStream) -> std::io::Result<()> {
    //
    // Method selection message from the client:
    //
    //      +----+----------+----------+
    //      |VER | NMETHODS | METHODS  |
    //      +----+----------+----------+
    //      | 1  |    1     | 1 to 255 |
    //      +----+----------+----------+

    let mut header = [0u8; 2];
    if socket.read_exact(&mut header).await.is_err() {
        return Ok(());
    }
    let [version, nmethods] = header;

    if version != SOCKS_VERSION {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "Unsupported SOCKS version",
        ));
    }

    let mut methods = [0u8; 255];
    let methods = &mut methods[..nmethods as usize];
    socket.read_exact(methods).await?;

    //
    // No reason to support GSSAPI
    //

    let chosen = [METHOD_USERPASS, METHOD_NO_AUTH]
        .into_iter()
        .find(|m| methods.contains(m))
        .unwrap_or(METHOD_NONE_ACCEPTABLE);

    match chosen {
        METHOD_USERPASS => {
            socket.write_all(&[SOCKS_VERSION, METHOD_USERPASS]).await?;
            validate_password(&mut socket).await?;
        }
        METHOD_NO_AUTH => {
            socket.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        }
        _ => {
            socket
                .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
                .await?;
            return Ok(());
        }
    }

    //
    //  The SOCKS request is formed as follows:
    //
    //        +----+-----+-------+------+----------+----------+
    //        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //        +----+-----+-------+------+----------+----------+
    //        | 1  |  1  | X'00' |  1   | Variable |    2     |
    //        +----+-----+-------+------+----------+----------+
    //

    let mut head = [0u8; 4];
    socket.read_exact(&mut head).await?;
    let [version, cmd, _rsv, atyp] = head;

    if version != SOCKS_VERSION {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "Unsupported SOCKS version",
        ));
    }

    let target: SocketAddr = read_target(&mut socket, atyp).await?;

    match cmd {
        CMD_CONNECT => handle_connect(socket, target).await?,
        CMD_BIND => handle_bind(socket, target.ip()).await?,
        CMD_UDP_ASSOCIATE => handle_udp_associate(socket, target).await?,
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Unsupported SOCKS command",
            ));
        }
    }

    Ok(())
}
