use std::{collections::HashMap, fmt};

use super::NetworkErrorCode;

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
impl MacOsKeychainCredentialStore {
    pub fn new(service: &str) -> Result<Self, NetworkErrorCode> {
        if service != "net.kysion.kyclash.networking" && service != "net.kysion.kyclash.test" {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            service: service.to_owned(),
        })
    }
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
        assert!(MacOsKeychainCredentialStore::new("net.kysion.kyclash.networking").is_ok());
        assert!(MacOsKeychainCredentialStore::new("net.kysion.kyclash.test").is_ok());
        assert!(matches!(
            MacOsKeychainCredentialStore::new("untrusted.service"),
            Err(NetworkErrorCode::InvalidConfiguration)
        ));
    }
}
