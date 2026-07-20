#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use app_lib::networking::{NETWORK_IPC_PROTOCOL_VERSION, SidecarHandshake};

    let mut args = std::env::args().skip(1);
    let socket_path = args.next().ok_or_else(|| anyhow::anyhow!("missing socket path"))?;
    let instance_id = args.next().ok_or_else(|| anyhow::anyhow!("missing instance id"))?;
    if args.next().is_some() {
        anyhow::bail!("unexpected command-line argument");
    }

    let mut auth_token = String::new();
    std::io::BufReader::new(std::io::stdin()).read_line(&mut auth_token)?;
    let auth_token = auth_token.trim_end_matches(['\r', '\n']);
    if auth_token.is_empty() {
        anyhow::bail!("empty authentication token");
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut stream = loop {
        match UnixStream::connect(&socket_path) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };

    let handshake = SidecarHandshake {
        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
        instance_id,
        auth_proof: auth_token.to_owned(),
    };
    serde_json::to_writer(&mut stream, &handshake)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    loop {
        std::thread::park_timeout(Duration::from_secs(60));
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("kyclash-network-mock is not implemented on this platform");
    std::process::exit(1);
}
