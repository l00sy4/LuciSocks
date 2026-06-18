# LuciSocks

LuciSocks is performant SOCKS5 server that can also bind on a Tailnet IP.

### Usage

LuciSocks can listen on multiple interfaces, as specified in the hardcoded configuration. In the following example, LuciSocks is configured to listen on `127.0.0.1:1338` and to enforce username/password authentication. In this case, `creds` is the SHA-256 hash of the concatenation of the username and password. The config also instructs LuciSocks to listen on `10.10.1.25:1330`, but without any authentication. Finally, the `Tailnet` entry tells configures LuciSocks to bind port `2001` on the Tailnet IP address received after registering with the specified auth key.

```rust
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
        addr: "10.10.1.25:1330",
        creds: None,
    },
    Entry::Tailnet {
        auth_key: "ts-auth-key-...",
        port: 2001,
        creds: None,
    },
];
```
