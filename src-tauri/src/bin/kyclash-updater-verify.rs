use std::{env, fs::File, io::Read as _, path::Path};

use minisign_verify::{PublicKey, Signature};

fn verify(artifact: &Path, signature: &Path, public_key: &Path) -> Result<(), &'static str> {
    let public_key = PublicKey::from_file(public_key).map_err(|_| "invalid public key")?;
    let signature = Signature::from_file(signature).map_err(|_| "invalid signature")?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|_| "signature verification failed")?;
    let mut artifact = File::open(artifact).map_err(|_| "cannot open artifact")?;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let length = artifact.read(&mut buffer).map_err(|_| "cannot read artifact")?;
        if length == 0 {
            break;
        }
        verifier.update(&buffer[..length]);
    }
    verifier.finalize().map_err(|_| "signature verification failed")
}

fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        eprintln!("Usage: kyclash-updater-verify <artifact> <artifact.sig> <minisign-public-key>");
        std::process::exit(2);
    }

    match verify(
        Path::new(&arguments[0]),
        Path::new(&arguments[1]),
        Path::new(&arguments[2]),
    ) {
        Ok(()) => println!("KyClash updater signature verified"),
        Err(message) => {
            eprintln!("KyClash updater verification failed: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const PUBLIC_KEY: &str = "untrusted comment: minisign public key\n\
RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
    const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\n\
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n\
trusted comment: timestamp:1633700835\tfile:test\tprehashed\n\
wLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==\n";

    #[test]
    fn verifies_known_prehashed_signature() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let artifact = directory.path().join("artifact");
        let signature = directory.path().join("artifact.sig");
        let public_key = directory.path().join("updater.pub");
        File::create(&artifact)?.write_all(b"test")?;
        File::create(&signature)?.write_all(SIGNATURE.as_bytes())?;
        File::create(&public_key)?.write_all(PUBLIC_KEY.as_bytes())?;

        assert_eq!(verify(&artifact, &signature, &public_key), Ok(()));
        Ok(())
    }

    #[test]
    fn rejects_invalid_signature_without_echoing_input() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let artifact = directory.path().join("artifact");
        let signature = directory.path().join("artifact.sig");
        let public_key = directory.path().join("updater.pub");
        File::create(&artifact)?.write_all(b"test")?;
        File::create(&signature)?.write_all(b"attacker-controlled-signature")?;
        File::create(&public_key)?.write_all(b"attacker-controlled-key")?;

        assert_eq!(verify(&artifact, &signature, &public_key), Err("invalid public key"));
        Ok(())
    }
}
