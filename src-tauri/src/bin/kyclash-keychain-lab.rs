#[cfg(target_os = "macos")]
mod macos {
    use std::env;

    use app_lib::networking::{
        CredentialMaterial, CredentialReference, CredentialStore as _, MacOsKeychainCredentialStore, NetworkErrorCode,
    };
    use ring::rand::{SecureRandom as _, SystemRandom};

    const CONFIRMATION_VARIABLE: &str = "KYCLASH_KEYCHAIN_LAB_CONFIRM";
    const CONFIRMATION_VALUE: &str = "authorized-disposable-macos-account";
    const REFERENCE: &str = "keychain:kyclash.test.synthetic.v1";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Cycle,
        Cleanup,
    }

    impl Mode {
        fn parse(arguments: &[String]) -> Result<Option<Self>, NetworkErrorCode> {
            match arguments {
                [argument] if argument == "--help" || argument == "-h" => Ok(None),
                [argument] if argument == "cycle" => Ok(Some(Self::Cycle)),
                [argument] if argument == "cleanup" => Ok(Some(Self::Cleanup)),
                _ => Err(NetworkErrorCode::InvalidConfiguration),
            }
        }
    }

    fn confirmed() -> bool {
        env::var(CONFIRMATION_VARIABLE).as_deref() == Ok(CONFIRMATION_VALUE)
    }

    fn open() -> Result<(MacOsKeychainCredentialStore, CredentialReference), NetworkErrorCode> {
        Ok((
            MacOsKeychainCredentialStore::new_test(),
            CredentialReference::parse(REFERENCE)?,
        ))
    }

    fn cleanup() -> Result<(), NetworkErrorCode> {
        let (mut store, reference) = open()?;
        match store.get(&reference) {
            Ok(material) => {
                drop(material);
                store.delete(&reference)?;
            }
            Err(NetworkErrorCode::AuthenticationFailed) => {}
            Err(error) => return Err(error),
        }
        if !matches!(store.get(&reference), Err(NetworkErrorCode::AuthenticationFailed)) {
            return Err(NetworkErrorCode::PermissionDenied);
        }
        Ok(())
    }

    fn cycle() -> Result<(), NetworkErrorCode> {
        let (mut store, reference) = open()?;
        match store.get(&reference) {
            Ok(material) => {
                drop(material);
                return Err(NetworkErrorCode::PermissionDenied);
            }
            Err(NetworkErrorCode::AuthenticationFailed) => {}
            Err(error) => return Err(error),
        }

        let mut expected = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut expected)
            .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
        store.put(&reference, CredentialMaterial::new(expected.to_vec())?)?;

        let verification = store.get(&reference).and_then(|loaded| {
            if loaded.expose() != expected {
                return Err(NetworkErrorCode::AuthenticationFailed);
            }
            Ok(())
        });
        expected.fill(0);
        let deletion = store.delete(&reference);
        verification?;
        deletion?;
        if !matches!(store.get(&reference), Err(NetworkErrorCode::AuthenticationFailed)) {
            return Err(NetworkErrorCode::PermissionDenied);
        }
        Ok(())
    }

    fn usage() {
        println!(
            "Usage: kyclash-keychain-lab <cycle|cleanup>\n\
             Fixed service/account only. Requires \
             {CONFIRMATION_VARIABLE}={CONFIRMATION_VALUE}. Disposable macOS accounts only."
        );
    }

    pub fn main() {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        match Mode::parse(&arguments) {
            Ok(None) => usage(),
            Ok(Some(_)) if !confirmed() => {
                eprintln!("KyClash Keychain lab refused: PermissionDenied");
                std::process::exit(1);
            }
            Ok(Some(Mode::Cycle)) => match cycle() {
                Ok(()) => println!("KyClash Keychain lab completed"),
                Err(error) => {
                    eprintln!("KyClash Keychain lab failed: {error:?}");
                    std::process::exit(1);
                }
            },
            Ok(Some(Mode::Cleanup)) => match cleanup() {
                Ok(()) => println!("KyClash Keychain lab cleanup completed"),
                Err(error) => {
                    eprintln!("KyClash Keychain lab cleanup failed: {error:?}");
                    std::process::exit(1);
                }
            },
            Err(_) => {
                usage();
                std::process::exit(2);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accepts_only_fixed_modes() {
            assert_eq!(Mode::parse(&["cycle".into()]), Ok(Some(Mode::Cycle)));
            assert_eq!(Mode::parse(&["cleanup".into()]), Ok(Some(Mode::Cleanup)));
            assert_eq!(Mode::parse(&["--help".into()]), Ok(None));
            assert_eq!(
                Mode::parse(&["cycle".into(), "another-account".into()]),
                Err(NetworkErrorCode::InvalidConfiguration)
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    macos::main();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("KyClash Keychain lab is available only on macOS");
    std::process::exit(1);
}
