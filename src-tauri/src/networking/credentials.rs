use std::{collections::HashMap, fmt};

use ring::rand::{SecureRandom as _, SystemRandom};

use super::{NetworkErrorCode, SidecarLaunchContext};

const KEYCHAIN_REFERENCE_PREFIX: &str = "keychain:";

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialReference(String);

impl CredentialReference {
    pub fn parse(value: &str) -> Result<Self, NetworkErrorCode> {
        let Some(identifier) = value.strip_prefix(KEYCHAIN_REFERENCE_PREFIX) else {
            return Err(NetworkErrorCode::InvalidConfiguration);
        };
        if identifier.is_empty()
            || identifier.len() > 128
            || !identifier.chars().enumerate().all(|(index, character)| {
                character.is_ascii_alphanumeric() || (index > 0 && matches!(character, '.' | '_' | ':' | '-'))
            })
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self(identifier.to_owned()))
    }

    pub fn keychain_account(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CredentialReference")
            .field(&"[REDACTED]")
            .finish()
    }
}

pub struct CredentialMaterial(Vec<u8>);

impl CredentialMaterial {
    pub fn new(bytes: Vec<u8>) -> Result<Self, NetworkErrorCode> {
        if bytes.is_empty() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialMaterial([REDACTED])")
    }
}

impl Drop for CredentialMaterial {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub trait CredentialStore {
    fn put(&mut self, reference: &CredentialReference, material: CredentialMaterial) -> Result<(), NetworkErrorCode>;
    fn get(&self, reference: &CredentialReference) -> Result<CredentialMaterial, NetworkErrorCode>;
    fn delete(&mut self, reference: &CredentialReference) -> Result<(), NetworkErrorCode>;
}

#[cfg(target_os = "macos")]
pub struct MacOsKeychainCredentialStore {
    service: String,
}

#[cfg(target_os = "macos")]
impl Default for MacOsKeychainCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl MacOsKeychainCredentialStore {
    pub fn new() -> Self {
        Self {
            service: "net.kysion.kyclash.networking".to_owned(),
        }
    }

    #[cfg(any(test, feature = "networking-keychain-lab"))]
    pub fn new_test() -> Self {
        Self {
            service: "net.kysion.kyclash.test".to_owned(),
        }
    }
}

pub fn resolve_or_generate_wireguard_material(
    store: &mut dyn CredentialStore,
    reference: &CredentialReference,
) -> Result<CredentialMaterial, NetworkErrorCode> {
    resolve_or_generate_with(store, reference, |bytes| {
        SystemRandom::new()
            .fill(bytes)
            .map_err(|_| NetworkErrorCode::AuthenticationFailed)
    })
}

pub fn prepare_sidecar_launch_context(
    instance_id: String,
    auth_token: Vec<u8>,
    identity_ref: &str,
    store: &mut dyn CredentialStore,
) -> Result<SidecarLaunchContext, NetworkErrorCode> {
    let reference = CredentialReference::parse(identity_ref)?;
    let material = resolve_or_generate_wireguard_material(store, &reference)?;
    let context = SidecarLaunchContext::new(instance_id, auth_token).with_private_key(material.expose().to_vec());
    Ok(context)
}

fn resolve_or_generate_with(
    store: &mut dyn CredentialStore,
    reference: &CredentialReference,
    generate: impl FnOnce(&mut [u8]) -> Result<(), NetworkErrorCode>,
) -> Result<CredentialMaterial, NetworkErrorCode> {
    match store.get(reference) {
        Ok(material) if material.expose().len() == 32 => return Ok(material),
        Ok(_) => return Err(NetworkErrorCode::AuthenticationFailed),
        Err(NetworkErrorCode::AuthenticationFailed) => {}
        Err(error) => return Err(error),
    }
    let mut bytes = vec![0_u8; 32];
    generate(&mut bytes)?;
    let persisted = CredentialMaterial::new(bytes.clone())?;
    store.put(reference, persisted)?;
    CredentialMaterial::new(bytes)
}

#[cfg(target_os = "macos")]
impl CredentialStore for MacOsKeychainCredentialStore {
    fn put(&mut self, reference: &CredentialReference, material: CredentialMaterial) -> Result<(), NetworkErrorCode> {
        security_framework::passwords::set_generic_password(
            &self.service,
            reference.keychain_account(),
            material.expose(),
        )
        .map_err(|_| NetworkErrorCode::PermissionDenied)
    }

    fn get(&self, reference: &CredentialReference) -> Result<CredentialMaterial, NetworkErrorCode> {
        let bytes = security_framework::passwords::generic_password(
            security_framework::passwords::PasswordOptions::new_generic_password(
                &self.service,
                reference.keychain_account(),
            ),
        )
        .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
        CredentialMaterial::new(bytes)
    }

    fn delete(&mut self, reference: &CredentialReference) -> Result<(), NetworkErrorCode> {
        security_framework::passwords::delete_generic_password(&self.service, reference.keychain_account())
            .map_err(|_| NetworkErrorCode::PermissionDenied)
    }
}

#[derive(Default)]
pub struct MemoryCredentialStore {
    values: HashMap<CredentialReference, CredentialMaterial>,
}

impl CredentialStore for MemoryCredentialStore {
    fn put(&mut self, reference: &CredentialReference, material: CredentialMaterial) -> Result<(), NetworkErrorCode> {
        self.values.insert(reference.clone(), material);
        Ok(())
    }

    fn get(&self, reference: &CredentialReference) -> Result<CredentialMaterial, NetworkErrorCode> {
        let material = self
            .values
            .get(reference)
            .ok_or(NetworkErrorCode::AuthenticationFailed)?;
        CredentialMaterial::new(material.expose().to_vec())
    }

    fn delete(&mut self, reference: &CredentialReference) -> Result<(), NetworkErrorCode> {
        self.values.remove(reference);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_requires_explicit_keychain_scheme_and_safe_identifier() {
        for invalid in [
            "device.test",
            "file:device.test",
            "keychain:",
            "keychain:-device",
            "keychain:device/../../secret",
        ] {
            assert_eq!(
                CredentialReference::parse(invalid),
                Err(NetworkErrorCode::InvalidConfiguration)
            );
        }
        let reference = CredentialReference::parse("keychain:device.test");
        assert!(reference.is_ok());
    }

    #[test]
    fn memory_store_round_trip_delete_and_debug_are_redacted() -> Result<(), NetworkErrorCode> {
        let reference = CredentialReference::parse("keychain:device.test")?;
        let secret = b"private-key-material";
        let material = CredentialMaterial::new(secret.to_vec())?;
        assert!(!format!("{reference:?}{material:?}").contains("private-key-material"));
        assert!(!format!("{reference:?}").contains("device.test"));

        let mut store = MemoryCredentialStore::default();
        store.put(&reference, material)?;
        let loaded = store.get(&reference)?;
        assert_eq!(loaded.expose(), secret);
        store.delete(&reference)?;
        assert!(matches!(
            store.get(&reference),
            Err(NetworkErrorCode::AuthenticationFailed)
        ));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_store_accepts_only_the_kyclash_service_namespace() {
        assert_eq!(
            MacOsKeychainCredentialStore::new().service,
            "net.kysion.kyclash.networking"
        );
        assert_eq!(
            MacOsKeychainCredentialStore::new_test().service,
            "net.kysion.kyclash.test"
        );
    }

    #[test]
    fn generated_wireguard_material_is_persisted_once_and_redacted() -> Result<(), NetworkErrorCode> {
        let reference = CredentialReference::parse("keychain:device.generated")?;
        let mut store = MemoryCredentialStore::default();
        let first = resolve_or_generate_with(&mut store, &reference, |bytes| {
            bytes.fill(0x5a);
            Ok(())
        })?;
        let second = resolve_or_generate_with(&mut store, &reference, |_| {
            Err(NetworkErrorCode::InvalidStateTransition)
        })?;
        assert_eq!(first.expose(), &[0x5a; 32]);
        assert_eq!(second.expose(), first.expose());
        assert!(!format!("{first:?}{second:?}").contains("5a"));
        Ok(())
    }

    #[test]
    fn launch_context_resolves_only_keychain_reference_and_remains_redacted() -> Result<(), NetworkErrorCode> {
        let reference = CredentialReference::parse("keychain:device.launch")?;
        let mut store = MemoryCredentialStore::default();
        store.put(&reference, CredentialMaterial::new(vec![0x66; 32])?)?;
        let context = prepare_sidecar_launch_context(
            "instance.launch".into(),
            vec![0x77; 32],
            "keychain:device.launch",
            &mut store,
        )?;
        assert_eq!(context.private_key(), &[0x66; 32]);
        assert!(!format!("{context:?}").contains("102"));
        assert_eq!(
            prepare_sidecar_launch_context("instance.bad".into(), vec![1; 32], "file:bad", &mut store),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "manual destructive lifecycle; run only in a disposable macOS account"]
    fn disposable_account_keychain_lifecycle_uses_test_namespace() -> Result<(), NetworkErrorCode> {
        let reference = CredentialReference::parse("keychain:kyclash.manual.lifecycle")?;
        let mut store = MacOsKeychainCredentialStore::new_test();
        let _ = store.delete(&reference);
        store.put(&reference, CredentialMaterial::new(vec![0x33; 32])?)?;
        assert_eq!(store.get(&reference)?.expose(), &[0x33; 32]);
        store.put(&reference, CredentialMaterial::new(vec![0x44; 32])?)?;
        assert_eq!(store.get(&reference)?.expose(), &[0x44; 32]);
        store.delete(&reference)
    }
}
