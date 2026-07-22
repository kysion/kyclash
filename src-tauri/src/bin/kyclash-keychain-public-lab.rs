//! Guest-only bridge from the run-bound KyClash test-service credential to a
//! peer public key. This binary is a disposable macOS VM fixture and is never
//! bundled in the KyClash application.

#[cfg(target_os = "macos")]
mod macos {
    use std::env;
    use std::ffi::{CStr, CString};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use app_lib::networking::{
        CredentialReference, CredentialStore as _, FilePolicyIdentityStore, MacOsKeychainCredentialStore,
        PolicyIdentityLabSnapshot, resolve_or_generate_wireguard_material_with_status,
    };
    use aws_lc_rs::agreement::{PrivateKey, X25519};
    use ring::digest::{SHA256, digest};
    use serde::Serialize;

    const RUNNER_ENVIRONMENT: &str = "local-virtualization-framework";
    const VM_CONFIRMATION: &str = "authorized-kyclash-virtualization-framework-vm";
    const RUNTIME_TARGET: &str = "kyclash-macos-lab-work";
    const BASE_DIR: &str = "/private/var/tmp/kyclash-networking-vm-lab";
    const SERVICE: &str = "net.kysion.kyclash.test";
    const PUBLIC_KEY_NAME: &str = "client-public.key";
    const CREATION_INTENT_NAME: &str = "credential-creating";
    const CREDENTIAL_STATE_NAME: &str = "credential-created";
    const PUBLIC_STATE_NAME: &str = "client-public-key-created";
    const POLICY_PREFLIGHT_NAME: &str = "policy-revision-preflight.json";
    const POLICY_APP_ID: &str = "net.kysion.kyclash";
    const MANIFEST_NAME: &str = "manifest.txt";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Error {
        Usage,
        Refused,
        InvalidState,
        AlreadyExists,
        Keychain,
        Crypto,
        Io,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ParsedCommand<'a> {
        Create { run_id: &'a str },
        Cleanup { run_id: &'a str },
        PolicyRevisionPreflight { run_id: &'a str, revision: u64 },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RunPaths {
        run_id: String,
        root: PathBuf,
        manifest: PathBuf,
        creation_intent: PathBuf,
        credential_state: PathBuf,
        public_state: PathBuf,
        public_key: PathBuf,
        policy_preflight: PathBuf,
        account: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct PolicyRevisionPreflight {
        schema_version: u8,
        run_id: String,
        candidate_revision: u64,
        record_state: String,
        record_revision: u64,
        record_key_id: Option<String>,
        record_envelope_sha256: Option<String>,
        app_data_root: String,
        app_data_root_sha256: String,
        checked_at: u64,
        decision: String,
    }

    fn valid_run_id(value: &str) -> bool {
        value.len() == 16
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    fn paths_for(run_id: &str) -> Result<RunPaths, Error> {
        if !valid_run_id(run_id) {
            return Err(Error::Usage);
        }
        let root = Path::new(BASE_DIR).join(run_id);
        Ok(RunPaths {
            run_id: run_id.to_owned(),
            manifest: root.join(MANIFEST_NAME),
            creation_intent: root.join(CREATION_INTENT_NAME),
            credential_state: root.join(CREDENTIAL_STATE_NAME),
            public_state: root.join(PUBLIC_STATE_NAME),
            public_key: root.join(PUBLIC_KEY_NAME),
            policy_preflight: root.join(POLICY_PREFLIGHT_NAME),
            account: format!("kyclash.vm.lab.{run_id}"),
            root,
        })
    }

    fn guest_confirmed() -> bool {
        if env::var("KYCLASH_RUNNER_ENVIRONMENT").as_deref() != Ok(RUNNER_ENVIRONMENT)
            || env::var("KYCLASH_VM_LAB_CONFIRM").as_deref() != Ok(VM_CONFIRMATION)
            || env::var("KYCLASH_RUNTIME_TARGET").as_deref() != Ok(RUNTIME_TARGET)
            || env::consts::ARCH != "aarch64"
        {
            return false;
        }

        let model = Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.model"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|model| model.trim().starts_with("VirtualMac"))
            .unwrap_or(false);
        if !model {
            return false;
        }
        if !matches!(fs::canonicalize("/var"), Ok(path) if path == Path::new("/private/var")) {
            return false;
        }

        Command::new("/usr/bin/sudo")
            .args(["-n", "true"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn file_shape(path: &Path, mode: u32, expected_len: Option<u64>) -> Result<(), Error> {
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidState)?;
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o7777 != mode
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || expected_len.is_some_and(|length| metadata.len() != length)
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn directory_shape(path: &Path, mode: u32) -> Result<(), Error> {
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidState)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o7777 != mode
            || metadata.nlink() < 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn write_creation_intent(paths: &RunPaths) -> Result<File, Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.creation_intent)
            .map_err(|_| Error::AlreadyExists)?;
        let record = format!(
            "schema_version=1\nrun_id={}\nservice={}\naccount={}\ncreated=0\n",
            paths.run_id, SERVICE, paths.account
        );
        if file.write_all(record.as_bytes()).and_then(|_| file.sync_all()).is_err()
            || file_shape(&paths.creation_intent, 0o600, Some(record.len() as u64)).is_err()
        {
            drop(file);
            let _ = fs::remove_file(&paths.creation_intent);
            return Err(Error::Io);
        }
        Ok(file)
    }

    fn mark_creation_intent_created(file: &mut File, paths: &RunPaths) -> Result<(), Error> {
        let record = format!(
            "schema_version=1\nrun_id={}\nservice={}\naccount={}\ncreated=1\n",
            paths.run_id, SERVICE, paths.account
        );
        file.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
        file.write_all(record.as_bytes()).map_err(|_| Error::Io)?;
        file.sync_all().map_err(|_| Error::Io)?;
        file_shape(&paths.creation_intent, 0o600, Some(record.len() as u64))
    }

    fn creation_intent_created(paths: &RunPaths) -> Result<bool, Error> {
        file_shape(&paths.creation_intent, 0o600, None)?;
        let marker = fs::read_to_string(&paths.creation_intent).map_err(|_| Error::InvalidState)?;
        if manifest_value(&marker, "schema_version")? != "1"
            || manifest_value(&marker, "run_id")? != paths.run_id
            || manifest_value(&marker, "service")? != SERVICE
            || manifest_value(&marker, "account")? != paths.account
        {
            return Err(Error::InvalidState);
        }
        match manifest_value(&marker, "created")? {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(Error::InvalidState),
        }
    }

    const fn require_created_transition(created: bool) -> Result<(), Error> {
        if created { Ok(()) } else { Err(Error::InvalidState) }
    }

    fn manifest_value<'a>(manifest: &'a str, key: &str) -> Result<&'a str, Error> {
        let mut values = manifest
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{key}=")));
        let value = values.next().ok_or(Error::InvalidState)?;
        if values.next().is_some() {
            return Err(Error::InvalidState);
        }
        Ok(value)
    }

    fn validate_fixture_manifest(paths: &RunPaths) -> Result<(), Error> {
        if fs::canonicalize(BASE_DIR).map_err(|_| Error::InvalidState)? != Path::new(BASE_DIR)
            || fs::canonicalize(&paths.root).map_err(|_| Error::InvalidState)? != paths.root
        {
            return Err(Error::InvalidState);
        }
        directory_shape(&paths.root, 0o700)?;
        file_shape(&paths.manifest, 0o600, None)?;
        let manifest = fs::read_to_string(&paths.manifest).map_err(|_| Error::InvalidState)?;
        if manifest_value(&manifest, "schema_version")? != "1"
            || manifest_value(&manifest, "run_id")? != paths.run_id
            || manifest_value(&manifest, "service")? != SERVICE
            || manifest_value(&manifest, "account")? != paths.account
            || manifest_value(&manifest, "credential_preflight")? != "absent"
            || manifest_value(&manifest, "public_key_path")? != paths.public_key.to_string_lossy()
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn path_components_are_not_symlinks(path: &Path) -> Result<(), Error> {
        if !path.is_absolute() {
            return Err(Error::InvalidState);
        }
        let mut current = PathBuf::from("/");
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                current.push(name);
                let metadata = match fs::symlink_metadata(&current) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => return Err(Error::InvalidState),
                };
                if metadata.file_type().is_symlink() {
                    return Err(Error::InvalidState);
                }
            }
        }
        Ok(())
    }

    fn passwd_home() -> Result<PathBuf, Error> {
        let uid = unsafe { libc::geteuid() };
        let mut password: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; 16 * 1024];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut password,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() || password.pw_dir.is_null() {
            return Err(Error::InvalidState);
        }
        let home = PathBuf::from(std::ffi::OsStr::from_bytes(unsafe {
            CStr::from_ptr(password.pw_dir).to_bytes()
        }));
        if !home.is_absolute() || home.as_os_str().as_bytes().contains(&0) {
            return Err(Error::InvalidState);
        }
        Ok(home)
    }

    fn ensure_policy_app_data_root(home: &Path, uid: libc::uid_t) -> Result<PathBuf, Error> {
        if !home.is_absolute() {
            return Err(Error::InvalidState);
        }
        path_components_are_not_symlinks(home)?;
        let parent = home.join("Library/Application Support");
        path_components_are_not_symlinks(&parent)?;
        let parent_metadata = fs::symlink_metadata(&parent).map_err(|_| Error::InvalidState)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != uid
            || parent_metadata.mode() & 0o022 != 0
        {
            return Err(Error::InvalidState);
        }
        let root = parent.join(POLICY_APP_ID);
        path_components_are_not_symlinks(&root)?;
        let root_name = CString::new(root.as_os_str().as_bytes()).map_err(|_| Error::InvalidState)?;
        let created = match unsafe { libc::mkdir(root_name.as_ptr(), 0o700) } {
            0 => true,
            -1 if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists => false,
            _ => return Err(Error::InvalidState),
        };
        if created {
            // mkdir(2) receives 0700 directly; there is no wider-permission
            // interval followed by chmod.  Sync the parent before publishing
            // the path to the production store.
            File::open(&parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| Error::Io)?;
        }
        let metadata = fs::symlink_metadata(&root).map_err(|_| Error::InvalidState)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(Error::InvalidState);
        }
        Ok(root)
    }

    fn policy_app_data_root() -> Result<PathBuf, Error> {
        let uid = unsafe { libc::geteuid() };
        // Tauri's macOS `app_data_dir()` is dirs::data_dir()/bundle-id. The
        // dirs crate prefers HOME over getpwuid_r, so require both sources to
        // identify the same absolute, non-symlinked account home before
        // deriving the exact production path.
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or(Error::InvalidState)?;
        if !home.is_absolute() || home != passwd_home()? {
            return Err(Error::InvalidState);
        }
        if fs::canonicalize(&home).map_err(|_| Error::InvalidState)? != home {
            return Err(Error::InvalidState);
        }
        ensure_policy_app_data_root(&home, uid)
    }

    fn policy_revision_preflight(
        paths: &RunPaths,
        revision: u64,
        app_data_root: &Path,
        snapshot: PolicyIdentityLabSnapshot,
        checked_at: u64,
    ) -> Result<PolicyRevisionPreflight, Error> {
        if revision == 0 || snapshot != PolicyIdentityLabSnapshot::Missing {
            return Err(Error::InvalidState);
        }
        let app_data_root_bytes = app_data_root.as_os_str().as_bytes();
        let app_data_root_text = std::str::from_utf8(app_data_root_bytes).map_err(|_| Error::InvalidState)?;
        Ok(PolicyRevisionPreflight {
            schema_version: 1,
            run_id: paths.run_id.clone(),
            candidate_revision: revision,
            record_state: "absent".to_owned(),
            record_revision: 0,
            record_key_id: None,
            record_envelope_sha256: None,
            app_data_root: app_data_root_text.to_owned(),
            app_data_root_sha256: sha256_hex(app_data_root_bytes),
            checked_at,
            decision: "new".to_owned(),
        })
    }

    fn write_policy_preflight(paths: &RunPaths, revision: u64) -> Result<(), Error> {
        if !guest_confirmed() {
            return Err(Error::Refused);
        }
        if revision == 0 {
            return Err(Error::Usage);
        }
        validate_fixture_manifest(paths)?;
        match fs::symlink_metadata(&paths.policy_preflight) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::AlreadyExists),
        }
        let app_data_root = policy_app_data_root()?;
        let store = FilePolicyIdentityStore::new(app_data_root.clone()).map_err(|_| Error::InvalidState)?;
        let transaction = store.begin().map_err(|_| Error::InvalidState)?;
        let snapshot = transaction.lab_snapshot().map_err(|_| Error::InvalidState)?;
        let checked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidState)?
            .as_secs();
        let preflight = policy_revision_preflight(paths, revision, &app_data_root, snapshot, checked_at)?;
        let bytes = serde_json::to_vec(&preflight).map_err(|_| Error::Io)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.policy_preflight)
            .map_err(|_| Error::AlreadyExists)?;
        if output
            .write_all(&bytes)
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.sync_all())
            .is_err()
            || file_shape(&paths.policy_preflight, 0o600, Some((bytes.len() + 1) as u64)).is_err()
        {
            drop(output);
            let _ = fs::remove_file(&paths.policy_preflight);
            return Err(Error::Io);
        }
        if File::open(&paths.root)
            .and_then(|directory| directory.sync_all())
            .is_err()
        {
            drop(output);
            let _ = fs::remove_file(&paths.policy_preflight);
            return Err(Error::Io);
        }
        if transaction.lab_finish().is_err() {
            drop(output);
            let _ = fs::remove_file(&paths.policy_preflight);
            let _ = File::open(&paths.root).and_then(|directory| directory.sync_all());
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn validate_fixture_state(paths: &RunPaths) -> Result<(), Error> {
        validate_fixture_manifest(paths)?;
        if paths.creation_intent.exists()
            || paths.credential_state.exists()
            || paths.public_state.exists()
            || paths.public_key.exists()
        {
            return Err(Error::AlreadyExists);
        }
        Ok(())
    }

    fn derive_public(private_bytes: &[u8]) -> Result<[u8; 32], Error> {
        if private_bytes.len() != 32 {
            return Err(Error::Crypto);
        }
        let private = PrivateKey::from_private_key(&X25519, private_bytes).map_err(|_| Error::Crypto)?;
        let public = private.compute_public_key().map_err(|_| Error::Crypto)?;
        let bytes = public.as_ref();
        if bytes.len() != 32 {
            return Err(Error::Crypto);
        }
        let mut result = [0_u8; 32];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    fn write_public_key(file: &mut File, path: &Path, public_key: &[u8; 32]) -> Result<(), Error> {
        if let Err(error) = file
            .set_len(0)
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(public_key))
            .and_then(|_| file.sync_all())
        {
            let _ = fs::remove_file(path);
            return Err(if error.kind() == std::io::ErrorKind::PermissionDenied {
                Error::Refused
            } else {
                Error::Io
            });
        }
        file_shape(path, 0o600, Some(32))?;
        Ok(())
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        digest(&SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn public_hash(public_key: &[u8; 32]) -> String {
        sha256_hex(public_key)
    }

    fn read_public_key(path: &Path) -> Result<[u8; 32], Error> {
        file_shape(path, 0o600, Some(32))?;
        let bytes = fs::read(path).map_err(|_| Error::InvalidState)?;
        bytes.try_into().map_err(|_| Error::InvalidState)
    }

    fn create(run_id: &str) -> Result<String, Error> {
        if !guest_confirmed() {
            return Err(Error::Refused);
        }
        let paths = paths_for(run_id)?;
        validate_fixture_state(&paths)?;

        // Reserve the exact output before touching Keychain.  This prevents a
        // second helper for the same run from racing the production lookup.
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.public_key)
            .map_err(|_| Error::AlreadyExists)?;
        let mut creation_intent = match write_creation_intent(&paths) {
            Ok(file) => file,
            Err(error) => {
                drop(output);
                let _ = fs::remove_file(&paths.public_key);
                return Err(error);
            }
        };

        let reference =
            CredentialReference::parse(&format!("keychain:{}", paths.account)).map_err(|_| Error::InvalidState)?;
        let mut store = MacOsKeychainCredentialStore::new_test();

        // The fixture's absent proof is part of the ownership boundary.  Do a
        // second read immediately before the production resolver and refuse
        // every pre-existing value, including a valid 32-byte value.
        match store.get_test_item(&reference) {
            Ok(None) => {}
            Ok(Some(material)) => {
                drop(material);
                drop(creation_intent);
                drop(output);
                let _ = fs::remove_file(&paths.creation_intent);
                let _ = fs::remove_file(&paths.public_key);
                return Err(Error::AlreadyExists);
            }
            Err(_) => {
                drop(creation_intent);
                drop(output);
                let _ = fs::remove_file(&paths.creation_intent);
                let _ = fs::remove_file(&paths.public_key);
                return Err(Error::Keychain);
            }
        }

        let (material, created) = match resolve_or_generate_wireguard_material_with_status(&mut store, &reference) {
            Ok(result) => result,
            Err(_) => {
                drop(creation_intent);
                drop(output);
                let _ = fs::remove_file(&paths.creation_intent);
                let _ = fs::remove_file(&paths.public_key);
                return Err(Error::Keychain);
            }
        };
        if !created {
            // A value appeared after the explicit absent check.  Never mark or
            // delete a value this helper did not create.
            drop(material);
            drop(creation_intent);
            drop(output);
            let _ = fs::remove_file(&paths.creation_intent);
            let _ = fs::remove_file(&paths.public_key);
            return Err(Error::AlreadyExists);
        }
        // Persist ownership immediately while the returned `created` status is
        // still in scope.  A failure is safe to roll back because this helper
        // has proven that it created the exact account.
        if mark_creation_intent_created(&mut creation_intent, &paths).is_err()
            || creation_intent_created(&paths) != Ok(true)
        {
            drop(material);
            // Never discard the only recovery witnesses until deletion has
            // been confirmed.  A Keychain delete can fail (for example while
            // the login Keychain is locked); in that case retain the intent
            // and reserved public file so cleanup can fail closed or the
            // disposable VM can be reverted with ownership evidence intact.
            let rolled_back = store.delete(&reference).is_ok() && matches!(store.get_test_item(&reference), Ok(None));
            drop(creation_intent);
            drop(output);
            if rolled_back {
                let _ = fs::remove_file(&paths.creation_intent);
                let _ = fs::remove_file(&paths.public_key);
                return Err(Error::Io);
            }
            return Err(Error::Keychain);
        }
        let public_key = match derive_public(material.expose()) {
            Ok(public_key) => public_key,
            Err(error) => {
                drop(material);
                drop(creation_intent);
                drop(output);
                let _ = fs::remove_file(&paths.public_key);
                return Err(error);
            }
        };
        drop(material);

        // Read the exact item again and compare only derived public material;
        // the private bytes never enter a log, argument, or output file.
        let verification = match store.get(&reference) {
            Ok(material) => material,
            Err(_) => {
                drop(creation_intent);
                drop(output);
                let _ = fs::remove_file(&paths.public_key);
                return Err(Error::Keychain);
            }
        };
        let verification_public = match derive_public(verification.expose()) {
            Ok(public_key) => public_key,
            Err(error) => {
                drop(verification);
                drop(creation_intent);
                drop(output);
                let _ = fs::remove_file(&paths.public_key);
                return Err(error);
            }
        };
        drop(verification);
        if verification_public != public_key {
            drop(output);
            let _ = fs::remove_file(&paths.public_key);
            return Err(Error::Keychain);
        }

        write_public_key(&mut output, &paths.public_key, &public_key)?;
        drop(creation_intent);
        Ok(public_hash(&public_key))
    }

    fn cleanup(run_id: &str) -> Result<Option<String>, Error> {
        if !guest_confirmed() {
            return Err(Error::Refused);
        }
        let paths = paths_for(run_id)?;
        validate_fixture_manifest(&paths)?;
        require_created_transition(creation_intent_created(&paths)?)?;
        // A crash or foreign write between the Keychain put and the durable
        // created=1 transition leaves ownership unprovable. The guard above
        // therefore rejects the cleanup before any Keychain read/delete.

        let reference =
            CredentialReference::parse(&format!("keychain:{}", paths.account)).map_err(|_| Error::InvalidState)?;
        let mut store = MacOsKeychainCredentialStore::new_test();
        // The public file is the second ownership witness. If a crash leaves
        // the durable created=1 marker but the public bytes are absent or
        // malformed, refuse to delete the Keychain value and preserve the VM
        // for recovery rather than guessing ownership.
        if !paths.public_key.exists() {
            return Err(Error::InvalidState);
        }
        let public_on_disk = read_public_key(&paths.public_key)?;

        let hash = match store.get_test_item(&reference) {
            Ok(Some(material)) => {
                let derived = derive_public(material.expose())?;
                drop(material);
                if public_on_disk != derived {
                    return Err(Error::InvalidState);
                }
                store.delete(&reference).map_err(|_| Error::Keychain)?;
                match store.get_test_item(&reference) {
                    Ok(None) => {}
                    Ok(Some(material)) => {
                        drop(material);
                        return Err(Error::Keychain);
                    }
                    Err(_) => return Err(Error::Keychain),
                }
                Some(public_hash(&derived))
            }
            Ok(None) => Some(public_hash(&public_on_disk)),
            Err(_) => return Err(Error::Keychain),
        };

        if paths.public_key.exists() {
            // The file was already shape-checked and, while a credential was
            // present, compared with the freshly derived public value.
            fs::remove_file(&paths.public_key).map_err(|_| Error::Io)?;
        }
        Ok(hash)
    }

    fn usage() {
        println!(
            "Usage: kyclash-keychain-public-lab <create|cleanup> --run-id <16-lowercase-hex>\n\
             Usage: kyclash-keychain-public-lab policy-revision-preflight --run-id <16-lowercase-hex> --revision <positive-integer>\n\
             Reads only the redacted policy identity record and writes a preflight\n\
             record into the exact disposable VM run directory."
        );
    }

    fn parse(arguments: &[String]) -> Result<Option<ParsedCommand<'_>>, Error> {
        match arguments {
            [command, flag, run_id] if flag == "--run-id" && command == "create" => {
                Ok(Some(ParsedCommand::Create { run_id }))
            }
            [command, flag, run_id] if flag == "--run-id" && command == "cleanup" => {
                Ok(Some(ParsedCommand::Cleanup { run_id }))
            }
            [command, run_flag, run_id, revision_flag, revision]
                if command == "policy-revision-preflight"
                    && run_flag == "--run-id"
                    && revision_flag == "--revision" =>
            {
                let revision = revision.parse::<u64>().map_err(|_| Error::Usage)?;
                if revision == 0 {
                    return Err(Error::Usage);
                }
                Ok(Some(ParsedCommand::PolicyRevisionPreflight { run_id, revision }))
            }
            [argument] if argument == "--help" || argument == "-h" => Ok(None),
            _ => Err(Error::Usage),
        }
    }

    pub fn main() {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        match parse(&arguments) {
            Ok(None) => usage(),
            Ok(Some(ParsedCommand::Create { run_id })) => match create(run_id) {
                Ok(hash) => {
                    println!("kyclash_keychain_public_lab=created");
                    println!("client_public_key_sha256={hash}");
                }
                Err(_) => {
                    eprintln!("KyClash keychain public lab failed");
                    std::process::exit(1);
                }
            },
            Ok(Some(ParsedCommand::Cleanup { run_id })) => match cleanup(run_id) {
                Ok(hash) => {
                    println!("kyclash_keychain_public_lab=cleanup-passed");
                    if let Some(hash) = hash {
                        println!("client_public_key_sha256={hash}");
                    }
                }
                Err(_) => {
                    eprintln!("KyClash keychain public lab cleanup failed");
                    std::process::exit(1);
                }
            },
            Ok(Some(ParsedCommand::PolicyRevisionPreflight { run_id, revision })) => {
                match paths_for(run_id).and_then(|paths| write_policy_preflight(&paths, revision)) {
                    Ok(()) => println!("kyclash_policy_revision_preflight=passed"),
                    Err(_) => {
                        eprintln!("KyClash policy revision preflight failed");
                        std::process::exit(1);
                    }
                }
            }
            Err(_) => {
                usage();
                std::process::exit(64);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io;
        use std::os::unix::fs::PermissionsExt as _;

        fn test_io_error(error: Error) -> io::Error {
            io::Error::other(format!("{error:?}"))
        }

        #[test]
        fn run_id_is_exactly_lowercase_hex() {
            assert!(valid_run_id("0123456789abcdef"));
            assert!(!valid_run_id("0123456789ABCDEf"));
            assert!(!valid_run_id("0123456789abcde"));
            assert!(!valid_run_id("0123456789abcdef0"));
            assert!(!valid_run_id("0123456789abcdeg"));
        }

        #[test]
        fn paths_are_run_bound_and_private_names_are_fixed() -> Result<(), Error> {
            let paths = paths_for("0123456789abcdef")?;
            assert_eq!(paths.account, "kyclash.vm.lab.0123456789abcdef");
            assert_eq!(
                paths.public_key,
                Path::new(BASE_DIR).join("0123456789abcdef/client-public.key")
            );
            assert!(!paths.public_key.to_string_lossy().contains(".."));
            Ok(())
        }

        #[test]
        fn derives_rfc7748_x25519_public_key_without_keychain() -> Result<(), Error> {
            let private = [
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf,
                0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
            ];
            // RFC 7748 §6.1 Alice private scalar and public value.
            let expected = [
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d,
                0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
            ];
            assert_eq!(derive_public(&private)?, expected);
            Ok(())
        }

        #[test]
        fn parser_rejects_arbitrary_output_and_secret_arguments() {
            assert_eq!(
                parse(&["create".into(), "--run-id".into(), "0123456789abcdef".into()]),
                Ok(Some(ParsedCommand::Create {
                    run_id: "0123456789abcdef"
                }))
            );
            assert_eq!(
                parse(&["cleanup".into(), "--run-id".into(), "0123456789abcdef".into()]),
                Ok(Some(ParsedCommand::Cleanup {
                    run_id: "0123456789abcdef"
                }))
            );
            assert_eq!(
                parse(&[
                    "policy-revision-preflight".into(),
                    "--run-id".into(),
                    "0123456789abcdef".into(),
                    "--revision".into(),
                    "42".into(),
                ]),
                Ok(Some(ParsedCommand::PolicyRevisionPreflight {
                    run_id: "0123456789abcdef",
                    revision: 42,
                }))
            );
            assert!(
                parse(&[
                    "create".into(),
                    "--run-id".into(),
                    "0123456789abcdef".into(),
                    "--private-key".into(),
                    "secret".into(),
                ])
                .is_err()
            );
        }

        #[test]
        fn policy_preflight_accepts_only_a_missing_production_record() -> Result<(), Error> {
            let paths = paths_for("0123456789abcdef")?;
            let root = Path::new("/Users/supen/Library/Application Support/net.kysion.kyclash");
            let preflight =
                policy_revision_preflight(&paths, 42, root, PolicyIdentityLabSnapshot::Missing, 1_800_000_000)?;
            assert_eq!(preflight.record_state, "absent");
            assert_eq!(preflight.decision, "new");
            assert_eq!(preflight.app_data_root, root.to_string_lossy());
            assert_eq!(preflight.app_data_root_sha256, sha256_hex(root.as_os_str().as_bytes()));

            for existing in [
                PolicyIdentityLabSnapshot::Legacy { revision: 41 },
                PolicyIdentityLabSnapshot::Identity {
                    revision: 41,
                    envelope_sha256: "a".repeat(64),
                    key_id: "lab.vm.0123456789abcdef".into(),
                },
            ] {
                assert_eq!(
                    policy_revision_preflight(&paths, 42, root, existing, 1_800_000_000),
                    Err(Error::InvalidState)
                );
            }
            Ok(())
        }

        #[test]
        fn app_data_root_is_created_atomically_with_private_mode() -> io::Result<()> {
            let home = tempfile::tempdir_in("/private/var/tmp")?;
            let support = home.path().join("Library/Application Support");
            fs::create_dir_all(&support)?;
            fs::set_permissions(&support, fs::Permissions::from_mode(0o700))?;
            let root = ensure_policy_app_data_root(home.path(), unsafe { libc::geteuid() }).map_err(test_io_error)?;
            let metadata = fs::symlink_metadata(root)?;
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700);
            Ok(())
        }

        #[test]
        fn creation_intent_is_exclusive_and_records_created_transition() -> io::Result<()> {
            let temporary = tempfile::tempdir()?;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
            let paths = RunPaths {
                run_id: "0123456789abcdef".into(),
                root: temporary.path().into(),
                manifest: temporary.path().join(MANIFEST_NAME),
                creation_intent: temporary.path().join(CREATION_INTENT_NAME),
                credential_state: temporary.path().join(CREDENTIAL_STATE_NAME),
                public_state: temporary.path().join(PUBLIC_STATE_NAME),
                public_key: temporary.path().join(PUBLIC_KEY_NAME),
                policy_preflight: temporary.path().join(POLICY_PREFLIGHT_NAME),
                account: "kyclash.vm.lab.0123456789abcdef".into(),
            };

            let mut intent = write_creation_intent(&paths).map_err(test_io_error)?;
            assert_eq!(creation_intent_created(&paths), Ok(false));
            assert!(matches!(write_creation_intent(&paths), Err(Error::AlreadyExists)));
            mark_creation_intent_created(&mut intent, &paths).map_err(test_io_error)?;
            assert_eq!(creation_intent_created(&paths), Ok(true));
            let record = fs::read_to_string(&paths.creation_intent)?;
            assert!(!record.contains("private"));
            assert!(!record.contains("material"));
            Ok(())
        }

        #[test]
        fn cleanup_requires_durable_ownership_transition() {
            assert_eq!(require_created_transition(false), Err(Error::InvalidState));
            assert_eq!(require_created_transition(true), Ok(()));
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    macos::main();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("KyClash keychain public lab is available only on macOS");
    std::process::exit(69);
}
