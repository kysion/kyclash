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
    /// Insert a credential only when the exact service/account is absent.
    ///
    /// Implementations must provide an atomic create-only operation: `Ok(true)`
    /// means this call created the item, while `Ok(false)` means an existing
    /// item won the race and was left untouched. This is deliberately separate
    /// from [`Self::put`], whose update semantics are retained for ordinary
    /// runtime use and the explicitly scoped manual lifecycle test.
    fn put_if_absent(
        &mut self,
        reference: &CredentialReference,
        material: CredentialMaterial,
    ) -> Result<bool, NetworkErrorCode>;
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

    #[cfg(any(test, feature = "networking-keychain-lab", feature = "networking-system-lab"))]
    pub fn new_test() -> Self {
        Self {
            service: "net.kysion.kyclash.test".to_owned(),
        }
    }

    /// Select the service namespace for the explicitly built runtime.
    ///
    /// A disposable production-feature VM candidate also enables the
    /// `networking-system-lab` feature so its scoped Keychain fixture can use
    /// only the KyClash test namespace. Ordinary production builds retain the
    /// production service and never compile that lab feature.
    #[cfg(any(feature = "networking-production", feature = "networking-system-lab"))]
    pub fn new_for_runtime() -> Self {
        #[cfg(feature = "networking-system-lab")]
        {
            Self::new_test()
        }
        #[cfg(not(feature = "networking-system-lab"))]
        {
            Self::new()
        }
    }

    /// Read the explicitly scoped lab item while preserving the distinction
    /// between an absent item and a Keychain access/lock failure.  The normal
    /// credential-store API intentionally collapses those failures into the
    /// application-level authentication error for runtime use; destructive
    /// fixture cleanup must not make that conversion because it would be able
    /// to report success while an inaccessible item still exists.
    #[cfg(any(feature = "networking-keychain-lab", feature = "networking-system-lab"))]
    pub fn get_test_item(
        &self,
        reference: &CredentialReference,
    ) -> Result<Option<CredentialMaterial>, NetworkErrorCode> {
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
        match security_framework::passwords::generic_password(
            security_framework::passwords::PasswordOptions::new_generic_password(
                &self.service,
                reference.keychain_account(),
            ),
        ) {
            Ok(bytes) => CredentialMaterial::new(bytes).map(Some),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(_) => Err(NetworkErrorCode::PermissionDenied),
        }
    }
}

pub fn resolve_or_generate_wireguard_material(
    store: &mut dyn CredentialStore,
    reference: &CredentialReference,
) -> Result<CredentialMaterial, NetworkErrorCode> {
    resolve_or_generate_with_status(store, reference, |bytes| {
        SystemRandom::new()
            .fill(bytes)
            .map_err(|_| NetworkErrorCode::AuthenticationFailed)
    })
    .map(|(material, _created)| material)
}

/// Resolve the production WireGuard material and report whether this call
/// created the Keychain value.  The status is used only by the disposable VM
/// fixture to establish exact ownership before deriving a public key; normal
/// application code should use [`resolve_or_generate_wireguard_material`].
#[cfg(any(feature = "networking-keychain-lab", feature = "networking-system-lab"))]
pub fn resolve_or_generate_wireguard_material_with_status(
    store: &mut dyn CredentialStore,
    reference: &CredentialReference,
) -> Result<(CredentialMaterial, bool), NetworkErrorCode> {
    resolve_or_generate_with_status(store, reference, |bytes| {
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

fn resolve_or_generate_with_status(
    store: &mut dyn CredentialStore,
    reference: &CredentialReference,
    generate: impl FnOnce(&mut [u8]) -> Result<(), NetworkErrorCode>,
) -> Result<(CredentialMaterial, bool), NetworkErrorCode> {
    match store.get(reference) {
        Ok(material) if material.expose().len() == 32 => return Ok((material, false)),
        Ok(_) => return Err(NetworkErrorCode::AuthenticationFailed),
        Err(NetworkErrorCode::AuthenticationFailed) => {}
        Err(error) => return Err(error),
    }
    let mut bytes = vec![0_u8; 32];
    if let Err(error) = generate(&mut bytes) {
        bytes.fill(0);
        return Err(error);
    }
    let persisted = match CredentialMaterial::new(bytes.clone()) {
        Ok(material) => material,
        Err(error) => {
            bytes.fill(0);
            return Err(error);
        }
    };
    let created = match store.put_if_absent(reference, persisted) {
        Ok(created) => created,
        Err(error) => {
            bytes.fill(0);
            return Err(error);
        }
    };
    if !created {
        // A concurrent creator won the atomic insertion. Read its value
        // without modifying it and report `created=false`; callers that need
        // exact ownership (the disposable VM helper) fail closed on this
        // branch instead of claiming or deleting the foreign item.
        bytes.fill(0);
        let material = store.get(reference)?;
        if material.expose().len() != 32 {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        return Ok((material, false));
    }
    Ok((CredentialMaterial::new(bytes)?, true))
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

    fn put_if_absent(
        &mut self,
        reference: &CredentialReference,
        material: CredentialMaterial,
    ) -> Result<bool, NetworkErrorCode> {
        // `set_generic_password` performs find-then-update and is therefore
        // unsuitable for establishing ownership. SecItemAdd, exposed here as
        // `SecKeychain::add_generic_password`, is create-only and returns
        // errSecDuplicateItem without changing the existing value.
        const ERR_SEC_DUPLICATE_ITEM: i32 = -25_299;
        let keychain = security_framework::os::macos::keychain::SecKeychain::default()
            .map_err(|_| NetworkErrorCode::PermissionDenied)?;
        match keychain.add_generic_password(&self.service, reference.keychain_account(), material.expose()) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => Ok(false),
            Err(_) => Err(NetworkErrorCode::PermissionDenied),
        }
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

    fn put_if_absent(
        &mut self,
        reference: &CredentialReference,
        material: CredentialMaterial,
    ) -> Result<bool, NetworkErrorCode> {
        if self.values.contains_key(reference) {
            return Ok(false);
        }
        self.values.insert(reference.clone(), material);
        Ok(true)
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

    #[derive(Default)]
    struct ForeignWinsStore {
        value: Option<Vec<u8>>,
    }

    impl CredentialStore for ForeignWinsStore {
        fn put(
            &mut self,
            _reference: &CredentialReference,
            material: CredentialMaterial,
        ) -> Result<(), NetworkErrorCode> {
            self.value = Some(material.expose().to_vec());
            Ok(())
        }

        fn put_if_absent(
            &mut self,
            _reference: &CredentialReference,
            material: CredentialMaterial,
        ) -> Result<bool, NetworkErrorCode> {
            if self.value.is_none() {
                // Simulate another writer winning between the resolver's
                // initial absent read and its atomic create-only insertion.
                self.value = Some(vec![0xa5; 32]);
            }
            drop(material);
            Ok(false)
        }

        fn get(&self, _reference: &CredentialReference) -> Result<CredentialMaterial, NetworkErrorCode> {
            self.value
                .clone()
                .map(CredentialMaterial::new)
                .transpose()?
                .ok_or(NetworkErrorCode::AuthenticationFailed)
        }

        fn delete(&mut self, _reference: &CredentialReference) -> Result<(), NetworkErrorCode> {
            self.value = None;
            Ok(())
        }
    }

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
        let (first, first_created) = resolve_or_generate_with_status(&mut store, &reference, |bytes| {
            bytes.fill(0x5a);
            Ok(())
        })?;
        let (second, second_created) = resolve_or_generate_with_status(&mut store, &reference, |_| {
            Err(NetworkErrorCode::InvalidStateTransition)
        })?;
        assert!(first_created);
        assert!(!second_created);
        assert_eq!(first.expose(), &[0x5a; 32]);
        assert_eq!(second.expose(), first.expose());
        assert!(!format!("{first:?}{second:?}").contains("5a"));
        Ok(())
    }

    #[test]
    fn create_only_store_never_overwrites_foreign_material() -> Result<(), NetworkErrorCode> {
        let reference = CredentialReference::parse("keychain:device.race")?;
        let foreign = [0xa5; 32];
        let candidate = [0x5a; 32];
        let mut store = MemoryCredentialStore::default();
        store.put(&reference, CredentialMaterial::new(foreign.to_vec())?)?;

        assert!(!store.put_if_absent(&reference, CredentialMaterial::new(candidate.to_vec())?)?);
        assert_eq!(store.get(&reference)?.expose(), &foreign);

        // The resolver's duplicate branch must also report non-ownership and
        // preserve the exact foreign bytes, matching the Keychain SecItemAdd
        // duplicate outcome used by the macOS implementation.
        let (resolved, created) = resolve_or_generate_with_status(&mut store, &reference, |bytes| {
            bytes.copy_from_slice(&candidate);
            Ok(())
        })?;
        assert!(!created);
        assert_eq!(resolved.expose(), &foreign);
        assert_eq!(store.get(&reference)?.expose(), &foreign);
        Ok(())
    }

    #[test]
    fn resolver_race_returns_foreign_material_without_claiming_ownership() -> Result<(), NetworkErrorCode> {
        let reference = CredentialReference::parse("keychain:device.race-winner")?;
        let mut store = ForeignWinsStore::default();
        let (resolved, created) = resolve_or_generate_with_status(&mut store, &reference, |bytes| {
            bytes.fill(0x5a);
            Ok(())
        })?;
        assert!(!created);
        assert_eq!(resolved.expose(), &[0xa5; 32]);
        assert_eq!(store.get(&reference)?.expose(), &[0xa5; 32]);
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
