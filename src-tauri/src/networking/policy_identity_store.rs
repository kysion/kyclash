use std::{path::PathBuf, time::Duration};

use super::NetworkErrorCode;

#[cfg(unix)]
const NETWORKING_DIRECTORY_NAME: &str = "networking";
#[cfg(unix)]
const RECORD_FILE_NAME: &str = "policy-revision.json";
#[cfg(unix)]
const LOCK_FILE_NAME: &str = "policy-revision.lock";
#[cfg(unix)]
const RECORD_SCHEMA_VERSION: u8 = 2;
#[cfg(unix)]
const RECORD_MAX_BYTES: usize = 4 * 1024;
const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, PartialEq, Eq)]
pub struct PolicyIdentityCandidate {
    revision: u64,
    envelope_sha256: String,
    key_id: String,
    issued_at: u64,
    expires_at: u64,
}

impl PolicyIdentityCandidate {
    pub fn new(
        revision: u64,
        envelope_sha256: String,
        key_id: String,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, NetworkErrorCode> {
        let candidate = Self {
            revision,
            envelope_sha256,
            key_id,
            issued_at,
            expires_at,
        };
        candidate.validate_shape()?;
        Ok(candidate)
    }

    fn validate_shape(&self) -> Result<(), NetworkErrorCode> {
        if self.revision == 0
            || self.expires_at <= self.issued_at
            || !valid_digest(&self.envelope_sha256)
            || !valid_key_id(&self.key_id)
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn validate_at(&self, now: u64) -> Result<(), NetworkErrorCode> {
        self.validate_shape()?;
        if self.issued_at > now || self.expires_at <= now {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }
}

impl std::fmt::Debug for PolicyIdentityCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyIdentityCandidate")
            .field("revision", &self.revision)
            .field("key_id", &self.key_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyIdentityDecision {
    New,
    Advance { previous_revision: u64, legacy: bool },
    Idempotent,
    Reject,
}

/// Redacted snapshot exposed only to the disposable VM system-lab helper.
/// The owning transaction retains the exact production lock until it is
/// dropped, so callers can durably publish their preflight evidence before a
/// production writer can proceed.
#[cfg(feature = "networking-system-lab")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyIdentityLabSnapshot {
    Missing,
    Legacy {
        revision: u64,
    },
    Identity {
        revision: u64,
        envelope_sha256: String,
        key_id: String,
    },
}

#[derive(Debug, Clone)]
pub struct FilePolicyIdentityStore {
    app_data_root: PathBuf,
    lock_timeout: Duration,
}

impl FilePolicyIdentityStore {
    pub fn new(app_data_root: PathBuf) -> Result<Self, NetworkErrorCode> {
        if !app_data_root.is_absolute() {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(Self {
            app_data_root,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
        })
    }

    #[cfg(all(test, unix))]
    const fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    #[cfg(unix)]
    pub fn begin(&self) -> Result<PolicyIdentityTransaction, NetworkErrorCode> {
        unix::begin(self)
    }

    #[cfg(not(unix))]
    pub fn begin(&self) -> Result<PolicyIdentityTransaction, NetworkErrorCode> {
        let _ = (&self.app_data_root, self.lock_timeout);
        Err(NetworkErrorCode::InvalidConfiguration)
    }
}

#[cfg(unix)]
pub struct PolicyIdentityTransaction {
    app_data_path: PathBuf,
    app_data: std::fs::File,
    app_data_identity: unix::DirectoryIdentity,
    networking: std::fs::File,
    networking_identity: unix::DirectoryIdentity,
    _lock: std::fs::File,
    lock_identity: unix::DirectoryIdentity,
    snapshot: unix::RecordSnapshot,
    stored: Option<unix::StoredRecord>,
    candidate: Option<PolicyIdentityCandidate>,
    decision: Option<PolicyIdentityDecision>,
}

#[cfg(not(unix))]
pub struct PolicyIdentityTransaction;

impl std::fmt::Debug for PolicyIdentityTransaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyIdentityTransaction(<redacted>)")
    }
}

#[cfg(unix)]
impl PolicyIdentityTransaction {
    #[cfg(feature = "networking-system-lab")]
    pub fn lab_snapshot(&self) -> Result<PolicyIdentityLabSnapshot, NetworkErrorCode> {
        unix::ensure_attached(self)?;
        if unix::read_record_snapshot(&self.networking)? != self.snapshot {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(match self.stored.as_ref() {
            None => PolicyIdentityLabSnapshot::Missing,
            Some(unix::StoredRecord::Legacy(record)) => PolicyIdentityLabSnapshot::Legacy {
                revision: record.revision,
            },
            Some(unix::StoredRecord::Identity(record)) => PolicyIdentityLabSnapshot::Identity {
                revision: record.revision,
                envelope_sha256: record.envelope_sha256.clone(),
                key_id: record.key_id.clone(),
            },
        })
    }

    #[cfg(feature = "networking-system-lab")]
    pub fn lab_finish(self) -> Result<(), NetworkErrorCode> {
        unix::ensure_attached(&self)?;
        if unix::read_record_snapshot(&self.networking)? != self.snapshot {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }

    pub fn classify(
        &mut self,
        candidate: PolicyIdentityCandidate,
        now: u64,
    ) -> Result<PolicyIdentityDecision, NetworkErrorCode> {
        if self.candidate.is_some() || self.decision.is_some() {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        candidate.validate_at(now)?;
        unix::ensure_attached(self)?;
        let decision = match self.stored.as_ref() {
            None => PolicyIdentityDecision::New,
            Some(unix::StoredRecord::Legacy(record)) => {
                if candidate.revision > record.revision {
                    PolicyIdentityDecision::Advance {
                        previous_revision: record.revision,
                        legacy: true,
                    }
                } else {
                    PolicyIdentityDecision::Reject
                }
            }
            Some(unix::StoredRecord::Identity(record)) => {
                if candidate.revision > record.revision {
                    PolicyIdentityDecision::Advance {
                        previous_revision: record.revision,
                        legacy: false,
                    }
                } else if candidate.revision == record.revision
                    && candidate.envelope_sha256 == record.envelope_sha256
                    && candidate.key_id == record.key_id
                {
                    PolicyIdentityDecision::Idempotent
                } else {
                    PolicyIdentityDecision::Reject
                }
            }
        };
        self.candidate = Some(candidate);
        self.decision = Some(decision);
        Ok(decision)
    }

    pub fn commit(mut self, now: u64) -> Result<PolicyIdentityDecision, NetworkErrorCode> {
        let candidate = self.candidate.take().ok_or(NetworkErrorCode::PolicySignatureInvalid)?;
        let decision = self.decision.take().ok_or(NetworkErrorCode::PolicySignatureInvalid)?;
        if decision == PolicyIdentityDecision::Reject {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        candidate.validate_at(now)?;
        if decision == PolicyIdentityDecision::Idempotent {
            unix::ensure_attached(&self)?;
            if unix::read_record_snapshot(&self.networking)? != self.snapshot {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            unix::ensure_attached(&self)?;
            if unix::read_record_snapshot(&self.networking)? != self.snapshot {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
        } else {
            unix::write_identity_record(
                &self.networking,
                &candidate,
                &self.snapshot,
                || {
                    unix::ensure_attached(&self)?;
                    if unix::read_record_snapshot(&self.networking)? != self.snapshot {
                        return Err(NetworkErrorCode::PolicySignatureInvalid);
                    }
                    Ok(())
                },
                || unix::ensure_attached(&self),
            )?;
        }
        Ok(decision)
    }
}

#[cfg(not(unix))]
impl PolicyIdentityTransaction {
    pub fn classify(
        &mut self,
        _candidate: PolicyIdentityCandidate,
        _now: u64,
    ) -> Result<PolicyIdentityDecision, NetworkErrorCode> {
        Err(NetworkErrorCode::InvalidConfiguration)
    }

    pub fn commit(self, _now: u64) -> Result<PolicyIdentityDecision, NetworkErrorCode> {
        Err(NetworkErrorCode::InvalidConfiguration)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric() || (index > 0 && matches!(character, '.' | '_' | ':' | '-'))
        })
}

#[cfg(unix)]
mod unix {
    use std::{
        ffi::{CStr, CString},
        fs::File,
        io::{Read as _, Write as _},
        os::{
            fd::{AsRawFd as _, FromRawFd as _, RawFd},
            unix::ffi::OsStrExt as _,
        },
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant},
    };

    use ring::rand::{SecureRandom as _, SystemRandom};
    use serde::{Deserialize, Serialize};

    #[cfg(test)]
    use std::cell::Cell;

    use super::{
        FilePolicyIdentityStore, LOCK_FILE_NAME, NETWORKING_DIRECTORY_NAME, NetworkErrorCode, PolicyIdentityCandidate,
        PolicyIdentityTransaction, RECORD_FILE_NAME, RECORD_MAX_BYTES, RECORD_SCHEMA_VERSION, valid_digest,
        valid_key_id,
    };

    static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(test)]
    thread_local! {
        static TEST_FAULT: Cell<Option<&'static str>> = const { Cell::new(None) };
    }

    #[cfg(test)]
    pub(super) struct TestFaultGuard;

    #[cfg(test)]
    impl Drop for TestFaultGuard {
        fn drop(&mut self) {
            TEST_FAULT.set(None);
        }
    }

    #[cfg(test)]
    pub(super) fn inject_test_fault(point: &'static str) -> TestFaultGuard {
        TEST_FAULT.set(Some(point));
        TestFaultGuard
    }

    #[cfg(test)]
    fn fault_injected(point: &str) -> bool {
        TEST_FAULT.get() == Some(point)
    }

    #[cfg(not(test))]
    const fn fault_injected(_point: &str) -> bool {
        false
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct DirectoryIdentity {
        device: libc::dev_t,
        inode: libc::ino_t,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct FileIdentity {
        device: libc::dev_t,
        inode: libc::ino_t,
        length: libc::off_t,
        modified_seconds: libc::time_t,
        modified_nanoseconds: libc::c_long,
        changed_seconds: libc::time_t,
        changed_nanoseconds: libc::c_long,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum RecordSnapshot {
        Missing,
        Present { bytes: Vec<u8>, identity: FileIdentity },
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct LegacyRecord {
        schema_version: u8,
        pub(super) revision: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct IdentityRecord {
        schema_version: u8,
        pub(super) revision: u64,
        pub(super) envelope_sha256: String,
        pub(super) key_id: String,
    }

    #[derive(Debug, Clone)]
    pub(super) enum StoredRecord {
        Legacy(LegacyRecord),
        Identity(IdentityRecord),
    }

    #[derive(Deserialize)]
    struct VersionProbe {
        schema_version: u8,
    }

    pub(super) fn begin(store: &FilePolicyIdentityStore) -> Result<PolicyIdentityTransaction, NetworkErrorCode> {
        let app_data = open_directory_path(&store.app_data_root)?;
        let app_data_stat = fstat(app_data.as_raw_fd())?;
        validate_directory(&app_data_stat, false)?;
        let app_data_identity = directory_identity(&app_data_stat);

        let networking_name = cstring(NETWORKING_DIRECTORY_NAME)?;
        if fault_injected("mkdirat") {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let created = match mkdirat(app_data.as_raw_fd(), &networking_name, 0o700) {
            Ok(()) => true,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => false,
            Err(_) => return Err(NetworkErrorCode::PolicySignatureInvalid),
        };
        if created && (fault_injected("ancestor_fsync") || fsync(app_data.as_raw_fd()).is_err()) {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let networking = open_directory_at(app_data.as_raw_fd(), &networking_name)?;
        let networking_stat = fstat(networking.as_raw_fd())?;
        validate_directory(&networking_stat, true)?;
        let networking_identity = directory_identity(&networking_stat);

        if fault_injected("lock_open") {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let lock = open_lock_file(&networking)?;
        acquire_lock(&lock, store.lock_timeout)?;
        let lock_stat = fstat(lock.as_raw_fd())?;
        validate_private_regular(&lock_stat)?;
        let lock_identity = directory_identity(&lock_stat);

        let transaction = PolicyIdentityTransaction {
            app_data_path: store.app_data_root.clone(),
            app_data,
            app_data_identity,
            networking,
            networking_identity,
            _lock: lock,
            lock_identity,
            snapshot: RecordSnapshot::Missing,
            stored: None,
            candidate: None,
            decision: None,
        };
        ensure_attached(&transaction)?;
        let snapshot = read_record_snapshot(&transaction.networking)?;
        let stored = parse_record(&snapshot)?;
        Ok(PolicyIdentityTransaction {
            snapshot,
            stored,
            ..transaction
        })
    }

    pub(super) fn ensure_attached(transaction: &PolicyIdentityTransaction) -> Result<(), NetworkErrorCode> {
        let current_root = open_directory_path(&transaction.app_data_path)?;
        let root_stat = fstat(current_root.as_raw_fd())?;
        validate_directory(&root_stat, false)?;
        if directory_identity(&root_stat) != transaction.app_data_identity {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let networking_name = cstring(NETWORKING_DIRECTORY_NAME)?;
        let current_leaf = open_directory_at(transaction.app_data.as_raw_fd(), &networking_name)?;
        let leaf_stat = fstat(current_leaf.as_raw_fd())?;
        validate_directory(&leaf_stat, true)?;
        if directory_identity(&leaf_stat) != transaction.networking_identity {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let held_lock_stat = fstat(transaction._lock.as_raw_fd())?;
        validate_private_regular(&held_lock_stat)?;
        if directory_identity(&held_lock_stat) != transaction.lock_identity {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let lock_name = cstring(LOCK_FILE_NAME)?;
        let named_lock = open_regular_at(transaction.networking.as_raw_fd(), &lock_name, libc::O_RDONLY)?;
        let named_lock_stat = fstat(named_lock.as_raw_fd())?;
        validate_private_regular(&named_lock_stat)?;
        if directory_identity(&named_lock_stat) != transaction.lock_identity {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }

    fn open_directory_path(path: &std::path::Path) -> Result<File, NetworkErrorCode> {
        let encoded = CString::new(path.as_os_str().as_bytes()).map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        let descriptor = unsafe {
            libc::open(
                encoded.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        file_from_descriptor(descriptor)
    }

    fn open_directory_at(parent: RawFd, name: &CStr) -> Result<File, NetworkErrorCode> {
        let descriptor = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        file_from_descriptor(descriptor)
    }

    fn open_lock_file(networking: &File) -> Result<File, NetworkErrorCode> {
        let name = cstring(LOCK_FILE_NAME)?;
        let create_flags =
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let descriptor = unsafe { libc::openat(networking.as_raw_fd(), name.as_ptr(), create_flags, 0o600) };
        let (file, created) = if descriptor >= 0 {
            (unsafe { File::from_raw_fd(descriptor) }, true)
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
            let existing = unsafe {
                libc::openat(
                    networking.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            (file_from_descriptor(existing)?, false)
        } else {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        };
        if created
            && (unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
                || file.sync_all().is_err()
                || fsync(networking.as_raw_fd()).is_err())
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        validate_private_regular(&fstat(file.as_raw_fd())?)?;
        Ok(file)
    }

    fn open_regular_at(parent: RawFd, name: &CStr, access: libc::c_int) -> Result<File, NetworkErrorCode> {
        let descriptor = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                access | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        file_from_descriptor(descriptor)
    }

    fn acquire_lock(file: &File, timeout: Duration) -> Result<(), NetworkErrorCode> {
        let deadline = Instant::now().checked_add(timeout).unwrap_or_else(Instant::now);
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                if Instant::now() >= deadline {
                    return Err(NetworkErrorCode::PolicySignatureInvalid);
                }
                continue;
            }
            let blocked = matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
            );
            if !blocked || Instant::now() >= deadline {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub(super) fn read_record_snapshot(networking: &File) -> Result<RecordSnapshot, NetworkErrorCode> {
        let name = cstring(RECORD_FILE_NAME)?;
        if fault_injected("record_open") {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let descriptor = unsafe {
            libc::openat(
                networking.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(RecordSnapshot::Missing)
            } else {
                Err(NetworkErrorCode::PolicySignatureInvalid)
            };
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let before = fstat(file.as_raw_fd())?;
        validate_private_regular(&before)?;
        let expected_len = usize::try_from(before.st_size).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        if expected_len == 0 || expected_len > RECORD_MAX_BYTES {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let mut bytes = Vec::with_capacity(expected_len);
        (&mut file)
            .take((RECORD_MAX_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let after = fstat(file.as_raw_fd())?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || modified_seconds(&before) != modified_seconds(&after)
            || modified_nanoseconds(&before) != modified_nanoseconds(&after)
            || changed_seconds(&before) != changed_seconds(&after)
            || changed_nanoseconds(&before) != changed_nanoseconds(&after)
            || bytes.len() != expected_len
            || bytes.len() > RECORD_MAX_BYTES
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(RecordSnapshot::Present {
            bytes,
            identity: file_identity(&before),
        })
    }

    fn parse_record(snapshot: &RecordSnapshot) -> Result<Option<StoredRecord>, NetworkErrorCode> {
        let RecordSnapshot::Present { bytes, .. } = snapshot else {
            return Ok(None);
        };
        let version: VersionProbe =
            serde_json::from_slice(bytes).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        match version.schema_version {
            1 => {
                let record: LegacyRecord =
                    serde_json::from_slice(bytes).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
                if record.schema_version != 1 || record.revision == 0 {
                    return Err(NetworkErrorCode::PolicySignatureInvalid);
                }
                Ok(Some(StoredRecord::Legacy(record)))
            }
            RECORD_SCHEMA_VERSION => {
                let record: IdentityRecord =
                    serde_json::from_slice(bytes).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
                if record.schema_version != RECORD_SCHEMA_VERSION
                    || record.revision == 0
                    || !valid_digest(&record.envelope_sha256)
                    || !valid_key_id(&record.key_id)
                {
                    return Err(NetworkErrorCode::PolicySignatureInvalid);
                }
                Ok(Some(StoredRecord::Identity(record)))
            }
            _ => Err(NetworkErrorCode::PolicySignatureInvalid),
        }
    }

    pub(super) fn write_identity_record<F, R>(
        networking: &File,
        candidate: &PolicyIdentityCandidate,
        previous_snapshot: &RecordSnapshot,
        before_rename: F,
        before_report: R,
    ) -> Result<(), NetworkErrorCode>
    where
        F: FnOnce() -> Result<(), NetworkErrorCode>,
        R: FnOnce() -> Result<(), NetworkErrorCode>,
    {
        let record = IdentityRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            revision: candidate.revision,
            envelope_sha256: candidate.envelope_sha256.clone(),
            key_id: candidate.key_id.clone(),
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        bytes.push(b'\n');
        if bytes.len() > RECORD_MAX_BYTES {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let temporary_name = random_temporary_name()?;
        if fault_injected("temp_create") {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let descriptor = unsafe { libc::openat(networking.as_raw_fd(), temporary_name.as_ptr(), flags, 0o600) };
        let mut temporary = file_from_descriptor(descriptor)?;
        let result = (|| {
            if unsafe { libc::fchmod(temporary.as_raw_fd(), 0o600) } != 0 {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            let created_stat = fstat(temporary.as_raw_fd())?;
            validate_private_regular(&created_stat)?;
            let identity = directory_identity(&created_stat);
            if fault_injected("temp_write") {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            temporary
                .write_all(&bytes)
                .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
            if fault_injected("temp_fsync") || temporary.sync_all().is_err() {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            let synchronized_stat = fstat(temporary.as_raw_fd())?;
            validate_private_regular(&synchronized_stat)?;
            if directory_identity(&synchronized_stat) != identity {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            verify_named_private_content(networking, &temporary_name, identity, &bytes)?;
            before_rename()?;
            #[cfg(test)]
            if fault_injected("temp_replace") {
                replace_temporary_for_test(networking, &temporary_name)?;
            }
            // Re-open the pathname after every potentially adversarial check.
            // The descriptor identity and exact bytes must still name the
            // create-new file immediately before the atomic rename.
            verify_named_private_content(networking, &temporary_name, identity, &bytes)?;
            #[cfg(test)]
            if fault_injected("temp_replace_after_verify") {
                replace_temporary_for_test(networking, &temporary_name)?;
            }
            let record_name = cstring(RECORD_FILE_NAME)?;
            let replacing = matches!(previous_snapshot, RecordSnapshot::Present { .. });
            #[cfg(test)]
            if !replacing && fault_injected("fresh_record_occupant_before_publish") {
                create_active_record_occupant_for_test(networking, &record_name)?;
            }
            if fault_injected("renameat") {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            publish_record(networking, &temporary_name, &record_name, replacing)?;
            #[cfg(test)]
            if replacing && fault_injected("retired_replace_after_exchange") {
                replace_temporary_for_test(networking, &temporary_name)?;
            }
            if replacing && verify_retired_snapshot(networking, &temporary_name, previous_snapshot).is_err() {
                rollback_publication(networking, &temporary_name, &record_name, previous_snapshot)?;
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            if verify_named_private_content(networking, &record_name, identity, &bytes).is_err() {
                rollback_publication(networking, &temporary_name, &record_name, previous_snapshot)?;
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            if fault_injected("parent_fsync") || fsync(networking.as_raw_fd()).is_err() {
                return Err(NetworkErrorCode::PolicySignatureInvalid);
            }
            verify_named_private_content(networking, &record_name, identity, &bytes)?;
            before_report()?;
            verify_named_private_content(networking, &record_name, identity, &bytes)
        })();
        drop(temporary);
        result
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    fn publish_record(
        networking: &File,
        temporary_name: &CStr,
        record_name: &CStr,
        replacing: bool,
    ) -> Result<(), NetworkErrorCode> {
        let flags = if replacing {
            rustix::fs::RenameFlags::EXCHANGE
        } else {
            rustix::fs::RenameFlags::NOREPLACE
        };
        rustix::fs::renameat_with(networking, temporary_name, networking, record_name, flags)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
    fn publish_record(
        _networking: &File,
        _temporary_name: &CStr,
        _record_name: &CStr,
        _replacing: bool,
    ) -> Result<(), NetworkErrorCode> {
        Err(NetworkErrorCode::InvalidConfiguration)
    }

    fn verify_retired_snapshot(
        networking: &File,
        temporary_name: &CStr,
        snapshot: &RecordSnapshot,
    ) -> Result<(), NetworkErrorCode> {
        let RecordSnapshot::Present { bytes, identity } = snapshot else {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        };
        let retired = open_regular_at(networking.as_raw_fd(), temporary_name, libc::O_RDONLY)?;
        let retired_status = fstat(retired.as_raw_fd())?;
        validate_private_regular(&retired_status)?;
        // RENAME_EXCHANGE changes the inode ctime even when the file itself is
        // otherwise untouched.  Compare the stable inode, size, and mtime
        // fields here; the exact bytes are checked below.  The transaction
        // already compares the complete snapshot (including ctime) directly
        // before publication.
        if !retired_identity_matches(&retired_status, identity) {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        verify_named_private_content(
            networking,
            temporary_name,
            DirectoryIdentity {
                device: identity.device,
                inode: identity.inode,
            },
            bytes,
        )
    }

    fn rollback_publication(
        networking: &File,
        temporary_name: &CStr,
        record_name: &CStr,
        previous_snapshot: &RecordSnapshot,
    ) -> Result<(), NetworkErrorCode> {
        #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
        {
            if matches!(previous_snapshot, RecordSnapshot::Present { .. }) {
                rustix::fs::renameat_with(
                    networking,
                    temporary_name,
                    networking,
                    record_name,
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
                fsync(networking.as_raw_fd()).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
                verify_retired_snapshot(networking, record_name, previous_snapshot)?;
            } else {
                let quarantine_name = random_temporary_name()?;
                rustix::fs::renameat_with(
                    networking,
                    record_name,
                    networking,
                    quarantine_name.as_c_str(),
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
                fsync(networking.as_raw_fd()).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
                if read_record_snapshot(networking)? != RecordSnapshot::Missing {
                    return Err(NetworkErrorCode::PolicySignatureInvalid);
                }
            }
            Ok(())
        }
        #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
        {
            let _ = (networking, temporary_name, record_name, previous_snapshot);
            Err(NetworkErrorCode::InvalidConfiguration)
        }
    }

    #[cfg(test)]
    fn replace_temporary_for_test(networking: &File, temporary_name: &CStr) -> Result<(), NetworkErrorCode> {
        let displaced = cstring(".policy-revision.displaced.test")?;
        if unsafe {
            libc::renameat(
                networking.as_raw_fd(),
                temporary_name.as_ptr(),
                networking.as_raw_fd(),
                displaced.as_ptr(),
            )
        } != 0
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let replacement = unsafe {
            libc::openat(
                networking.as_raw_fd(),
                temporary_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        let mut replacement = file_from_descriptor(replacement)?;
        if unsafe { libc::fchmod(replacement.as_raw_fd(), 0o600) } != 0 {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        replacement
            .write_all(b"replacement")
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        replacement
            .sync_all()
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)
    }

    #[cfg(test)]
    fn create_active_record_occupant_for_test(networking: &File, record_name: &CStr) -> Result<(), NetworkErrorCode> {
        let descriptor = unsafe {
            libc::openat(
                networking.as_raw_fd(),
                record_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        let mut occupant = file_from_descriptor(descriptor)?;
        if unsafe { libc::fchmod(occupant.as_raw_fd(), 0o600) } != 0 {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        occupant
            .write_all(b"active-name-occupant")
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        occupant
            .sync_all()
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        fsync(networking.as_raw_fd()).map_err(|_| NetworkErrorCode::PolicySignatureInvalid)
    }

    fn random_temporary_name() -> Result<CString, NetworkErrorCode> {
        use std::fmt::Write as _;

        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut entropy = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut entropy)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let mut suffix = String::with_capacity(entropy.len() * 2);
        for byte in entropy {
            write!(&mut suffix, "{byte:02x}").map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        }
        cstring(&format!(
            ".policy-revision.{}.{sequence}.{suffix}.tmp",
            std::process::id()
        ))
    }

    fn verify_named_private_content(
        networking: &File,
        name: &CStr,
        expected_identity: DirectoryIdentity,
        expected_bytes: &[u8],
    ) -> Result<(), NetworkErrorCode> {
        let mut file = open_regular_at(networking.as_raw_fd(), name, libc::O_RDONLY)?;
        let before = fstat(file.as_raw_fd())?;
        validate_private_regular(&before)?;
        if directory_identity(&before) != expected_identity
            || usize::try_from(before.st_size).ok() != Some(expected_bytes.len())
            || expected_bytes.len() > RECORD_MAX_BYTES
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        let mut bytes = Vec::with_capacity(expected_bytes.len());
        (&mut file)
            .take((RECORD_MAX_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| NetworkErrorCode::PolicySignatureInvalid)?;
        let after = fstat(file.as_raw_fd())?;
        validate_private_regular(&after)?;
        if directory_identity(&after) != expected_identity
            || before.st_size != after.st_size
            || modified_seconds(&before) != modified_seconds(&after)
            || modified_nanoseconds(&before) != modified_nanoseconds(&after)
            || changed_seconds(&before) != changed_seconds(&after)
            || changed_nanoseconds(&before) != changed_nanoseconds(&after)
            || bytes != expected_bytes
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }

    fn validate_directory(status: &libc::stat, leaf: bool) -> Result<(), NetworkErrorCode> {
        let mode = status.st_mode & libc::S_IFMT;
        let permissions = status.st_mode & 0o777;
        if mode != libc::S_IFDIR
            || status.st_uid != unsafe { libc::geteuid() }
            || permissions & 0o022 != 0
            || (leaf && permissions & 0o700 != 0o700)
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }

    fn validate_private_regular(status: &libc::stat) -> Result<(), NetworkErrorCode> {
        if status.st_mode & libc::S_IFMT != libc::S_IFREG
            || status.st_uid != unsafe { libc::geteuid() }
            || status.st_nlink != 1
            || status.st_mode & 0o777 != 0o600
        {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(())
    }

    const fn directory_identity(status: &libc::stat) -> DirectoryIdentity {
        DirectoryIdentity {
            device: status.st_dev,
            inode: status.st_ino,
        }
    }

    const fn file_identity(status: &libc::stat) -> FileIdentity {
        FileIdentity {
            device: status.st_dev,
            inode: status.st_ino,
            length: status.st_size,
            modified_seconds: modified_seconds(status),
            modified_nanoseconds: modified_nanoseconds(status),
            changed_seconds: changed_seconds(status),
            changed_nanoseconds: changed_nanoseconds(status),
        }
    }

    const fn retired_identity_matches(status: &libc::stat, identity: &FileIdentity) -> bool {
        status.st_dev == identity.device
            && status.st_ino == identity.inode
            && status.st_size == identity.length
            && modified_seconds(status) == identity.modified_seconds
            && modified_nanoseconds(status) == identity.modified_nanoseconds
    }

    fn fstat(descriptor: RawFd) -> Result<libc::stat, NetworkErrorCode> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(descriptor, status.as_mut_ptr()) } != 0 {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(unsafe { status.assume_init() })
    }

    fn file_from_descriptor(descriptor: RawFd) -> Result<File, NetworkErrorCode> {
        if descriptor < 0 {
            return Err(NetworkErrorCode::PolicySignatureInvalid);
        }
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn cstring(value: &str) -> Result<CString, NetworkErrorCode> {
        CString::new(value).map_err(|_| NetworkErrorCode::InvalidConfiguration)
    }

    fn mkdirat(parent: RawFd, name: &CStr, mode: libc::mode_t) -> std::io::Result<()> {
        if unsafe { libc::mkdirat(parent, name.as_ptr(), mode) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn fsync(descriptor: RawFd) -> std::io::Result<()> {
        if unsafe { libc::fsync(descriptor) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    const fn modified_seconds(status: &libc::stat) -> libc::time_t {
        status.st_mtime
    }

    const fn modified_nanoseconds(status: &libc::stat) -> libc::c_long {
        status.st_mtime_nsec
    }

    const fn changed_seconds(status: &libc::stat) -> libc::time_t {
        status.st_ctime
    }

    const fn changed_nanoseconds(status: &libc::stat) -> libc::c_long {
        status.st_ctime_nsec
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        env,
        ffi::CString,
        fs,
        os::unix::ffi::OsStrExt as _,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
        path::{Path, PathBuf},
        process::{Child, Command},
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    const WORKER_ROOT_ENV: &str = "KYCLASH_POLICY_STORE_TEST_ROOT";
    const WORKER_REVISION_ENV: &str = "KYCLASH_POLICY_STORE_TEST_REVISION";
    const WORKER_DIGEST_ENV: &str = "KYCLASH_POLICY_STORE_TEST_DIGEST";
    const WORKER_EXPECT_ENV: &str = "KYCLASH_POLICY_STORE_TEST_EXPECT";
    const WORKER_DELAY_ENV: &str = "KYCLASH_POLICY_STORE_TEST_DELAY_MS";
    const WORKER_READY_ENV: &str = "KYCLASH_POLICY_STORE_TEST_READY";

    fn candidate(revision: u64, digest_byte: char) -> anyhow::Result<PolicyIdentityCandidate> {
        PolicyIdentityCandidate::new(
            revision,
            digest_byte.to_string().repeat(64),
            "policy.test".into(),
            100,
            200,
        )
        .map_err(|error| anyhow::anyhow!("candidate: {error:?}"))
    }

    fn store(root: &std::path::Path) -> anyhow::Result<FilePolicyIdentityStore> {
        FilePolicyIdentityStore::new(root.to_path_buf()).map_err(|error| anyhow::anyhow!("store: {error:?}"))
    }

    fn net<T>(result: Result<T, NetworkErrorCode>) -> anyhow::Result<T> {
        result.map_err(|error| anyhow::anyhow!("{error:?}"))
    }

    fn worker_command(
        root: &Path,
        revision: u64,
        digest: char,
        expected: &str,
        delay: Duration,
        ready: &Path,
    ) -> anyhow::Result<Child> {
        let executable = env::current_exe()?;
        Ok(Command::new(executable)
            .arg("--exact")
            .arg("networking::policy_identity_store::tests::policy_identity_process_worker")
            .arg("--nocapture")
            .env(WORKER_ROOT_ENV, root)
            .env(WORKER_REVISION_ENV, revision.to_string())
            .env(WORKER_DIGEST_ENV, digest.to_string())
            .env(WORKER_EXPECT_ENV, expected)
            .env(WORKER_DELAY_ENV, delay.as_millis().to_string())
            .env(WORKER_READY_ENV, ready)
            .spawn()?)
    }

    fn wait_ready(path: &Path) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            if Instant::now() >= deadline {
                return Err(anyhow::anyhow!("policy identity worker did not become ready"));
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    fn wait_success(mut child: Child) -> anyhow::Result<()> {
        let status = child.wait()?;
        if !status.success() {
            return Err(anyhow::anyhow!("policy identity worker failed: {status}"));
        }
        Ok(())
    }

    fn read_identity(path: &Path) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::from_slice(&fs::read(
            path.join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME),
        )?)?)
    }

    fn assert_stable_metadata(before: &fs::Metadata, after: &fs::Metadata) {
        assert_eq!(after.dev(), before.dev());
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.size(), before.size());
        assert_eq!(after.mtime(), before.mtime());
        assert_eq!(after.mtime_nsec(), before.mtime_nsec());
        assert_eq!(after.mode() & 0o777, before.mode() & 0o777);
        assert_eq!(after.nlink(), before.nlink());
    }

    fn changed_time(metadata: &fs::Metadata) -> (i64, i64) {
        (metadata.ctime(), metadata.ctime_nsec())
    }

    #[test]
    fn policy_identity_process_worker() -> anyhow::Result<()> {
        let Some(root) = env::var_os(WORKER_ROOT_ENV).map(PathBuf::from) else {
            return Ok(());
        };
        let revision = env::var(WORKER_REVISION_ENV)?.parse::<u64>()?;
        let digest = env::var(WORKER_DIGEST_ENV)?
            .chars()
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing digest selector"))?;
        let expected = env::var(WORKER_EXPECT_ENV)?;
        let delay = Duration::from_millis(env::var(WORKER_DELAY_ENV)?.parse::<u64>()?);
        let ready = PathBuf::from(env::var_os(WORKER_READY_ENV).ok_or_else(|| anyhow::anyhow!("missing ready path"))?);

        let mut transaction = net(store(&root)?.begin())?;
        fs::write(&ready, b"locked")?;
        if expected == "hold" {
            thread::sleep(Duration::from_secs(30));
            return Ok(());
        }
        thread::sleep(delay);
        let decision = net(transaction.classify(candidate(revision, digest)?, 150))?;
        match expected.as_str() {
            "accept" => {
                if decision == PolicyIdentityDecision::Reject {
                    return Err(anyhow::anyhow!("candidate unexpectedly rejected"));
                }
                net(transaction.commit(150))?;
            }
            "reject" => {
                if decision != PolicyIdentityDecision::Reject
                    || transaction.commit(150) != Err(NetworkErrorCode::PolicySignatureInvalid)
                {
                    return Err(anyhow::anyhow!("candidate unexpectedly accepted"));
                }
            }
            _ => return Err(anyhow::anyhow!("unknown worker expectation")),
        }
        Ok(())
    }

    #[test]
    fn independent_processes_serialize_revision_and_same_revision_conflicts() -> anyhow::Result<()> {
        let lower_first = tempfile::tempdir()?;
        let lower_ready = lower_first.path().join("lower.ready");
        let higher_ready = lower_first.path().join("higher.ready");
        let lower = worker_command(
            lower_first.path(),
            42,
            'a',
            "accept",
            Duration::from_millis(120),
            &lower_ready,
        )?;
        wait_ready(&lower_ready)?;
        let higher = worker_command(lower_first.path(), 43, 'b', "accept", Duration::ZERO, &higher_ready)?;
        wait_success(lower)?;
        wait_success(higher)?;
        let record = read_identity(lower_first.path())?;
        assert_eq!(record["revision"], 43);
        assert_eq!(record["envelope_sha256"], "b".repeat(64));

        let higher_first = tempfile::tempdir()?;
        let higher_ready = higher_first.path().join("higher.ready");
        let lower_ready = higher_first.path().join("lower.ready");
        let higher = worker_command(
            higher_first.path(),
            43,
            'b',
            "accept",
            Duration::from_millis(120),
            &higher_ready,
        )?;
        wait_ready(&higher_ready)?;
        let lower = worker_command(higher_first.path(), 42, 'a', "reject", Duration::ZERO, &lower_ready)?;
        wait_success(higher)?;
        wait_success(lower)?;
        let record = read_identity(higher_first.path())?;
        assert_eq!(record["revision"], 43);
        assert_eq!(record["envelope_sha256"], "b".repeat(64));

        let same_revision = tempfile::tempdir()?;
        let first_ready = same_revision.path().join("first.ready");
        let second_ready = same_revision.path().join("second.ready");
        let first = worker_command(
            same_revision.path(),
            42,
            'a',
            "accept",
            Duration::from_millis(120),
            &first_ready,
        )?;
        wait_ready(&first_ready)?;
        let second = worker_command(same_revision.path(), 42, 'b', "reject", Duration::ZERO, &second_ready)?;
        wait_success(first)?;
        wait_success(second)?;
        let record = read_identity(same_revision.path())?;
        assert_eq!(record["revision"], 42);
        assert_eq!(record["envelope_sha256"], "a".repeat(64));
        Ok(())
    }

    #[test]
    fn killed_lock_holder_releases_kernel_lock_without_record_mutation() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let ready = directory.path().join("holder.ready");
        let mut holder = worker_command(directory.path(), 42, 'a', "hold", Duration::ZERO, &ready)?;
        wait_ready(&ready)?;
        holder.kill()?;
        let status = holder.wait()?;
        assert!(!status.success());

        let mut transaction = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(transaction.classify(candidate(42, 'a')?, 150))?,
            PolicyIdentityDecision::New
        );
        net(transaction.commit(150))?;
        assert_eq!(read_identity(directory.path())?["revision"], 42);
        Ok(())
    }

    #[cfg(feature = "networking-system-lab")]
    #[test]
    fn system_lab_snapshot_uses_the_production_lock_and_exact_record() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let empty = net(store(directory.path())?.begin())?;
        assert_eq!(net(empty.lab_snapshot())?, PolicyIdentityLabSnapshot::Missing);
        net(empty.lab_finish())?;

        let mut seed = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(seed.classify(candidate(42, 'a')?, 150))?,
            PolicyIdentityDecision::New
        );
        net(seed.commit(150))?;

        let present = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(present.lab_snapshot())?,
            PolicyIdentityLabSnapshot::Identity {
                revision: 42,
                envelope_sha256: "a".repeat(64),
                key_id: "policy.test".into(),
            }
        );
        net(present.lab_finish())?;
        Ok(())
    }

    #[cfg(feature = "networking-system-lab")]
    #[test]
    fn system_lab_finish_rejects_a_changed_snapshot_and_lock_is_exclusive() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let held = net(store(directory.path())?.begin())?;
        let blocked = store(directory.path())?
            .with_lock_timeout(Duration::from_millis(20))
            .begin();
        assert!(matches!(blocked, Err(NetworkErrorCode::PolicySignatureInvalid)));

        let record_path = directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
        fs::write(&record_path, br#"{"schema_version":1,"revision":42}"#)?;
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(held.lab_finish(), Err(NetworkErrorCode::PolicySignatureInvalid));
        Ok(())
    }

    #[cfg(feature = "networking-system-lab")]
    #[test]
    fn system_lab_finish_rejects_replaced_networking_directory_and_named_lock() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        let replaced = directory.path().join("networking.replaced");
        let transaction = net(store(directory.path())?.begin())?;
        fs::rename(&networking, &replaced)?;
        fs::create_dir(&networking)?;
        fs::set_permissions(&networking, fs::Permissions::from_mode(0o700))?;
        fs::write(networking.join(LOCK_FILE_NAME), b"")?;
        fs::set_permissions(networking.join(LOCK_FILE_NAME), fs::Permissions::from_mode(0o600))?;
        assert_eq!(transaction.lab_finish(), Err(NetworkErrorCode::PolicySignatureInvalid));

        let directory = tempfile::tempdir()?;
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        let lock = networking.join(LOCK_FILE_NAME);
        let transaction = net(store(directory.path())?.begin())?;
        fs::remove_file(&lock)?;
        fs::write(&lock, b"")?;
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
        assert_eq!(transaction.lab_finish(), Err(NetworkErrorCode::PolicySignatureInvalid));
        Ok(())
    }

    #[test]
    fn fresh_identity_and_exact_restart_are_durable_and_zero_write() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut first = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            net(first.classify(candidate(42, 'a')?, 150))?,
            PolicyIdentityDecision::New
        );
        assert_eq!(net(first.commit(150))?, PolicyIdentityDecision::New);

        let record_path = directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
        let before_bytes = fs::read(&record_path)?;
        let before = fs::metadata(&record_path)?;
        let mut second = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            net(second.classify(candidate(42, 'a')?, 151))?,
            PolicyIdentityDecision::Idempotent
        );
        assert_eq!(net(second.commit(151))?, PolicyIdentityDecision::Idempotent);
        let after = fs::metadata(&record_path)?;
        assert_eq!(fs::read(&record_path)?, before_bytes);
        assert_eq!(after.dev(), before.dev());
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.size(), before.size());
        assert_eq!(after.mtime(), before.mtime());
        assert_eq!(after.mtime_nsec(), before.mtime_nsec());
        assert_eq!(after.ctime(), before.ctime());
        assert_eq!(after.ctime_nsec(), before.ctime_nsec());
        assert_eq!(after.nlink(), before.nlink());
        assert_eq!(after.mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(directory.path().join(NETWORKING_DIRECTORY_NAME))?.mode() & 0o777,
            0o700
        );
        Ok(())
    }

    #[test]
    fn lower_and_same_revision_mismatch_reject_while_higher_advances() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut first = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        net(first.classify(candidate(42, 'a')?, 150))?;
        net(first.commit(150))?;

        for rejected in [candidate(41, 'a')?, candidate(42, 'b')?] {
            let mut transaction = store(directory.path())?
                .begin()
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
            assert_eq!(
                net(transaction.classify(rejected, 150))?,
                PolicyIdentityDecision::Reject
            );
            assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        }
        let mut advance = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            net(advance.classify(candidate(43, 'b')?, 150))?,
            PolicyIdentityDecision::Advance {
                previous_revision: 42,
                legacy: false
            }
        );
        net(advance.commit(150))?;
        let record: serde_json::Value = serde_json::from_slice(&fs::read(
            directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME),
        )?)?;
        assert_eq!(record["revision"], 43);
        Ok(())
    }

    #[test]
    fn legacy_record_is_a_floor_and_higher_revision_migrates_in_place() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        fs::create_dir(&networking)?;
        fs::set_permissions(&networking, fs::Permissions::from_mode(0o700))?;
        let record_path = networking.join(RECORD_FILE_NAME);
        fs::write(&record_path, br#"{"schema_version":1,"revision":42}"#)?;
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))?;

        for revision in [41, 42] {
            let mut transaction = store(directory.path())?
                .begin()
                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
            assert_eq!(
                net(transaction.classify(candidate(revision, 'a')?, 150))?,
                PolicyIdentityDecision::Reject
            );
            assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        }
        assert_eq!(fs::read(&record_path)?, br#"{"schema_version":1,"revision":42}"#);
        let mut migration = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            net(migration.classify(candidate(43, 'a')?, 150))?,
            PolicyIdentityDecision::Advance {
                previous_revision: 42,
                legacy: true
            }
        );
        net(migration.commit(150))?;
        let migrated: serde_json::Value = serde_json::from_slice(&fs::read(&record_path)?)?;
        assert_eq!(migrated["schema_version"], 2);
        assert_eq!(migrated["revision"], 43);
        Ok(())
    }

    #[test]
    fn commit_rechecks_expiry_and_exact_snapshot() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut expiring = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        net(expiring.classify(candidate(42, 'a')?, 150))?;
        assert_eq!(expiring.commit(200), Err(NetworkErrorCode::PolicySignatureInvalid));

        let mut transaction = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        net(transaction.classify(candidate(42, 'a')?, 150))?;
        let record_path = directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
        fs::write(&record_path, br#"{"schema_version":1,"revision":9}"#)?;
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        assert_eq!(fs::read(&record_path)?, br#"{"schema_version":1,"revision":9}"#);
        Ok(())
    }

    #[test]
    fn ctime_only_snapshot_change_is_rejected_even_when_inode_bytes_and_mtime_match() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut seed = net(store(directory.path())?.begin())?;
        net(seed.classify(candidate(42, 'a')?, 150))?;
        net(seed.commit(150))?;

        let record_path = directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
        let detached_path = directory
            .path()
            .join(NETWORKING_DIRECTORY_NAME)
            .join("policy-revision.ctime-test");
        let before_bytes = fs::read(&record_path)?;
        let before = fs::metadata(&record_path)?;
        let mut transaction = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(transaction.classify(candidate(42, 'a')?, 151))?,
            PolicyIdentityDecision::Idempotent
        );

        let deadline = Instant::now() + Duration::from_secs(3);
        let after = loop {
            thread::sleep(Duration::from_millis(20));
            fs::rename(&record_path, &detached_path)?;
            fs::rename(&detached_path, &record_path)?;
            let after = fs::metadata(&record_path)?;
            if changed_time(&after) != changed_time(&before) {
                break after;
            }
            if Instant::now() >= deadline {
                return Err(anyhow::anyhow!("rename-away/back did not advance record ctime"));
            }
        };

        assert_stable_metadata(&before, &after);
        assert_ne!(changed_time(&after), changed_time(&before));
        assert_eq!(fs::read(&record_path)?, before_bytes);
        assert_eq!(transaction.commit(151), Err(NetworkErrorCode::PolicySignatureInvalid));
        Ok(())
    }

    #[test]
    fn unsafe_record_and_lock_shapes_fail_closed_without_blocking() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        fs::create_dir(&networking)?;
        fs::set_permissions(&networking, fs::Permissions::from_mode(0o700))?;
        let target = networking.join("target");
        fs::write(&target, b"x")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        symlink(&target, networking.join(RECORD_FILE_NAME))?;
        assert!(matches!(
            store(directory.path())?.begin(),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        ));

        fs::remove_file(networking.join(RECORD_FILE_NAME))?;
        fs::hard_link(&target, networking.join(RECORD_FILE_NAME))?;
        assert!(matches!(
            store(directory.path())?.begin(),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        ));
        Ok(())
    }

    #[test]
    fn unsafe_directories_lock_and_record_types_modes_and_sizes_fail_closed() -> anyhow::Result<()> {
        let unsafe_root = tempfile::tempdir()?;
        fs::set_permissions(unsafe_root.path(), fs::Permissions::from_mode(0o770))?;
        assert!(matches!(
            store(unsafe_root.path())?.begin(),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        ));

        for leaf_shape in ["symlink", "file", "writable"] {
            let directory = tempfile::tempdir()?;
            let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
            match leaf_shape {
                "symlink" => symlink(directory.path(), &networking)?,
                "file" => fs::write(&networking, b"not-directory")?,
                "writable" => {
                    fs::create_dir(&networking)?;
                    fs::set_permissions(&networking, fs::Permissions::from_mode(0o770))?;
                }
                _ => return Err(anyhow::anyhow!("unknown leaf shape")),
            }
            assert!(matches!(
                store(directory.path())?.begin(),
                Err(NetworkErrorCode::PolicySignatureInvalid)
            ));
        }

        for lock_shape in ["symlink", "hardlink", "directory", "fifo", "mode"] {
            let directory = tempfile::tempdir()?;
            let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
            fs::create_dir(&networking)?;
            fs::set_permissions(&networking, fs::Permissions::from_mode(0o700))?;
            let lock = networking.join(LOCK_FILE_NAME);
            let target = networking.join("lock-target");
            match lock_shape {
                "symlink" => {
                    fs::write(&target, b"")?;
                    symlink(&target, &lock)?;
                }
                "hardlink" => {
                    fs::write(&target, b"")?;
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
                    fs::hard_link(&target, &lock)?;
                }
                "directory" => fs::create_dir(&lock)?,
                "fifo" => make_fifo(&lock)?,
                "mode" => {
                    fs::write(&lock, b"")?;
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))?;
                }
                _ => return Err(anyhow::anyhow!("unknown lock shape")),
            }
            assert!(matches!(
                store(directory.path())?.begin(),
                Err(NetworkErrorCode::PolicySignatureInvalid)
            ));
        }

        for record_shape in ["empty", "oversize", "directory", "fifo", "mode"] {
            let directory = tempfile::tempdir()?;
            let first = net(store(directory.path())?.begin())?;
            drop(first);
            let record = directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
            match record_shape {
                "empty" => fs::write(&record, b"")?,
                "oversize" => fs::write(&record, vec![b'a'; RECORD_MAX_BYTES + 1])?,
                "directory" => fs::create_dir(&record)?,
                "fifo" => make_fifo(&record)?,
                "mode" => {
                    fs::write(&record, br#"{"schema_version":1,"revision":1}"#)?;
                    fs::set_permissions(&record, fs::Permissions::from_mode(0o644))?;
                }
                _ => return Err(anyhow::anyhow!("unknown record shape")),
            }
            if record_shape != "directory" && record_shape != "fifo" && record_shape != "mode" {
                fs::set_permissions(&record, fs::Permissions::from_mode(0o600))?;
            }
            assert!(matches!(
                store(directory.path())?.begin(),
                Err(NetworkErrorCode::PolicySignatureInvalid)
            ));
        }
        Ok(())
    }

    fn make_fifo(path: &Path) -> anyhow::Result<()> {
        let encoded = CString::new(path.as_os_str().as_bytes())?;
        if unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    #[test]
    fn lock_is_cross_instance_and_bounded() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let first = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let second = store(directory.path())?.with_lock_timeout(Duration::from_millis(25));
        assert!(matches!(second.begin(), Err(NetworkErrorCode::PolicySignatureInvalid)));
        drop(first);
        assert!(second.begin().is_ok());
        Ok(())
    }

    #[test]
    fn replaced_lock_inode_is_detected_before_classification_or_commit() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut detached = net(store(directory.path())?.begin())?;
        let lock_path = directory.path().join(NETWORKING_DIRECTORY_NAME).join(LOCK_FILE_NAME);
        fs::remove_file(&lock_path)?;
        fs::write(&lock_path, b"")?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;

        let mut current = net(store(directory.path())?.begin())?;
        assert_eq!(
            detached.classify(candidate(42, 'a')?, 150),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(
            net(current.classify(candidate(42, 'a')?, 150))?,
            PolicyIdentityDecision::New
        );
        net(current.commit(150))?;

        let mut after_classify = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(after_classify.classify(candidate(43, 'b')?, 150))?,
            PolicyIdentityDecision::Advance {
                previous_revision: 42,
                legacy: false
            }
        );
        fs::remove_file(&lock_path)?;
        fs::write(&lock_path, b"")?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            after_classify.commit(150),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        );
        assert_eq!(read_identity(directory.path())?["revision"], 42);
        Ok(())
    }

    #[test]
    fn deletion_truncation_corruption_and_same_byte_replacement_are_detected() -> anyhow::Result<()> {
        for mutation in ["delete", "truncate", "corrupt", "replace_same"] {
            let directory = tempfile::tempdir()?;
            let mut seed = net(store(directory.path())?.begin())?;
            net(seed.classify(candidate(42, 'a')?, 150))?;
            net(seed.commit(150))?;
            let record_path = directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
            let original = fs::read(&record_path)?;
            let mut transaction = net(store(directory.path())?.begin())?;
            net(transaction.classify(candidate(43, 'b')?, 150))?;
            match mutation {
                "delete" => fs::remove_file(&record_path)?,
                "truncate" => fs::write(&record_path, b"")?,
                "corrupt" => fs::write(&record_path, b"not-json")?,
                "replace_same" => {
                    fs::remove_file(&record_path)?;
                    fs::write(&record_path, &original)?;
                    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600))?;
                }
                _ => return Err(anyhow::anyhow!("unknown mutation")),
            }
            assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
            if mutation == "replace_same" {
                assert_eq!(fs::read(&record_path)?, original);
            }
        }
        Ok(())
    }

    #[test]
    fn deterministic_filesystem_faults_fail_closed_and_preserve_random_private_orphans() -> anyhow::Result<()> {
        for point in ["mkdirat", "ancestor_fsync", "lock_open", "record_open"] {
            let directory = tempfile::tempdir()?;
            let _fault = unix::inject_test_fault(point);
            assert!(matches!(
                store(directory.path())?.begin(),
                Err(NetworkErrorCode::PolicySignatureInvalid)
            ));
            assert!(
                !directory
                    .path()
                    .join(NETWORKING_DIRECTORY_NAME)
                    .join(RECORD_FILE_NAME)
                    .exists()
            );
        }

        for point in ["temp_create", "temp_write", "temp_fsync", "renameat"] {
            let directory = tempfile::tempdir()?;
            let mut transaction = net(store(directory.path())?.begin())?;
            net(transaction.classify(candidate(42, 'a')?, 150))?;
            let _fault = unix::inject_test_fault(point);
            assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
            let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
            assert!(!networking.join(RECORD_FILE_NAME).exists());
            let temporary_count = fs::read_dir(&networking)?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count();
            let expected_orphans = if point == "temp_create" { 0 } else { 1 };
            assert_eq!(temporary_count, expected_orphans);
        }

        let directory = tempfile::tempdir()?;
        let mut transaction = net(store(directory.path())?.begin())?;
        net(transaction.classify(candidate(42, 'a')?, 150))?;
        {
            let _fault = unix::inject_test_fault("parent_fsync");
            assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        }
        assert_eq!(read_identity(directory.path())?["revision"], 42);
        let mut recovery = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(recovery.classify(candidate(42, 'a')?, 150))?,
            PolicyIdentityDecision::Idempotent
        );
        net(recovery.commit(150))?;
        Ok(())
    }

    #[test]
    fn temporary_path_substitution_is_detected_without_publishing_replacement() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut transaction = net(store(directory.path())?.begin())?;
        net(transaction.classify(candidate(42, 'a')?, 150))?;
        let _fault = unix::inject_test_fault("temp_replace");
        assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        assert!(!networking.join(RECORD_FILE_NAME).exists());
        assert!(!fs::read(networking.join(".policy-revision.displaced.test"))?.is_empty());
        assert!(fs::read_dir(networking)?.filter_map(Result::ok).any(|entry| {
            entry.file_name().to_string_lossy().ends_with(".tmp")
                && fs::read(entry.path()).is_ok_and(|bytes| bytes == b"replacement")
        }));
        Ok(())
    }

    #[test]
    fn fresh_publish_noreplace_never_overwrites_a_final_window_occupant() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut transaction = net(store(directory.path())?.begin())?;
        net(transaction.classify(candidate(42, 'a')?, 150))?;
        {
            let _fault = unix::inject_test_fault("fresh_record_occupant_before_publish");
            assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        }

        let record_path = directory.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
        assert_eq!(fs::read(&record_path)?, b"active-name-occupant");
        let occupant = fs::metadata(&record_path)?;
        assert_eq!(occupant.mode() & 0o777, 0o600);
        assert_eq!(occupant.nlink(), 1);
        assert_eq!(occupant.size(), b"active-name-occupant".len() as u64);
        assert!(matches!(
            store(directory.path())?.begin(),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        ));
        Ok(())
    }

    #[test]
    fn post_verification_path_substitution_rolls_back_new_and_advance_publication() -> anyhow::Result<()> {
        let fresh = tempfile::tempdir()?;
        let mut fresh_transaction = net(store(fresh.path())?.begin())?;
        net(fresh_transaction.classify(candidate(42, 'a')?, 150))?;
        {
            let _fault = unix::inject_test_fault("temp_replace_after_verify");
            assert_eq!(
                fresh_transaction.commit(150),
                Err(NetworkErrorCode::PolicySignatureInvalid)
            );
        }
        assert!(
            !fresh
                .path()
                .join(NETWORKING_DIRECTORY_NAME)
                .join(RECORD_FILE_NAME)
                .exists()
        );

        let advance = tempfile::tempdir()?;
        let mut seed = net(store(advance.path())?.begin())?;
        net(seed.classify(candidate(42, 'a')?, 150))?;
        net(seed.commit(150))?;
        let record_path = advance.path().join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME);
        let before_bytes = fs::read(&record_path)?;
        let before = fs::metadata(&record_path)?;
        let mut advancing = net(store(advance.path())?.begin())?;
        net(advancing.classify(candidate(43, 'b')?, 150))?;
        {
            let _fault = unix::inject_test_fault("temp_replace_after_verify");
            assert_eq!(advancing.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        }
        let after_rollback = fs::metadata(&record_path)?;
        assert_eq!(fs::read(&record_path)?, before_bytes);
        assert_stable_metadata(&before, &after_rollback);

        let mut retry = net(store(advance.path())?.begin())?;
        assert_eq!(
            net(retry.classify(candidate(42, 'a')?, 151))?,
            PolicyIdentityDecision::Idempotent
        );
        net(retry.commit(151))?;
        let after_retry = fs::metadata(&record_path)?;
        assert_eq!(fs::read(&record_path)?, before_bytes);
        assert_stable_metadata(&after_rollback, &after_retry);
        assert_eq!(changed_time(&after_retry), changed_time(&after_rollback));
        Ok(())
    }

    #[test]
    fn post_exchange_retired_replacement_fails_closed_against_disk_authority() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut seed = net(store(directory.path())?.begin())?;
        net(seed.classify(candidate(42, 'a')?, 150))?;
        net(seed.commit(150))?;
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        let record_path = networking.join(RECORD_FILE_NAME);
        let previous_bytes = fs::read(&record_path)?;

        let mut advancing = net(store(directory.path())?.begin())?;
        net(advancing.classify(candidate(43, 'b')?, 150))?;
        {
            let _fault = unix::inject_test_fault("retired_replace_after_exchange");
            assert_eq!(advancing.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        }

        assert_eq!(fs::read(&record_path)?, b"replacement");
        assert_eq!(
            fs::read(networking.join(".policy-revision.displaced.test"))?,
            previous_bytes
        );
        assert!(matches!(
            store(directory.path())?.begin(),
            Err(NetworkErrorCode::PolicySignatureInvalid)
        ));
        Ok(())
    }

    #[test]
    fn successful_advance_retires_exact_old_inode_under_random_private_ignored_name() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut seed = net(store(directory.path())?.begin())?;
        net(seed.classify(candidate(42, 'a')?, 150))?;
        net(seed.commit(150))?;
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        let record_path = networking.join(RECORD_FILE_NAME);
        let old_bytes = fs::read(&record_path)?;
        let old_metadata = fs::metadata(&record_path)?;

        let mut advancing = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(advancing.classify(candidate(43, 'b')?, 150))?,
            PolicyIdentityDecision::Advance {
                previous_revision: 42,
                legacy: false,
            }
        );
        net(advancing.commit(150))?;

        let retired = fs::read_dir(&networking)?
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".policy-revision.") && name.ends_with(".tmp")
            })
            .collect::<Vec<_>>();
        assert_eq!(retired.len(), 1);
        let retired_name = retired[0].file_name().to_string_lossy().into_owned();
        let random_fields = retired_name
            .strip_prefix(".policy-revision.")
            .and_then(|name| name.strip_suffix(".tmp"))
            .ok_or_else(|| anyhow::anyhow!("unexpected retired record name"))?
            .split('.')
            .collect::<Vec<_>>();
        assert_eq!(random_fields.len(), 3);
        assert_eq!(random_fields[0].parse::<u32>()?, std::process::id());
        random_fields[1].parse::<u64>()?;
        assert_eq!(random_fields[2].len(), 32);
        assert!(random_fields[2].bytes().all(|byte| byte.is_ascii_hexdigit()));

        let retired_path = retired[0].path();
        let retired_metadata = fs::metadata(&retired_path)?;
        assert_eq!(fs::read(&retired_path)?, old_bytes);
        assert_eq!(retired_metadata.dev(), old_metadata.dev());
        assert_eq!(retired_metadata.ino(), old_metadata.ino());
        assert_eq!(retired_metadata.size(), old_metadata.size());
        assert_eq!(retired_metadata.mode() & 0o777, 0o600);
        assert_eq!(retired_metadata.nlink(), 1);

        let active_before = fs::read(&record_path)?;
        let retired_before = fs::metadata(&retired_path)?;
        let mut restart = net(store(directory.path())?.begin())?;
        assert_eq!(
            net(restart.classify(candidate(43, 'b')?, 151))?,
            PolicyIdentityDecision::Idempotent
        );
        net(restart.commit(151))?;
        assert_eq!(fs::read(&record_path)?, active_before);
        assert_eq!(fs::read(&retired_path)?, old_bytes);
        let retired_after = fs::metadata(&retired_path)?;
        assert_stable_metadata(&retired_before, &retired_after);
        assert_eq!(changed_time(&retired_after), changed_time(&retired_before));
        Ok(())
    }

    #[test]
    fn parent_leaf_swap_is_detected_and_cannot_redirect_commit() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let mut transaction = store(directory.path())?
            .begin()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        net(transaction.classify(candidate(42, 'a')?, 150))?;
        let networking = directory.path().join(NETWORKING_DIRECTORY_NAME);
        let detached = directory.path().join("detached-networking");
        fs::rename(&networking, &detached)?;
        fs::create_dir(&networking)?;
        fs::set_permissions(&networking, fs::Permissions::from_mode(0o700))?;
        assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        assert!(!networking.join(RECORD_FILE_NAME).exists());
        assert!(!detached.join(RECORD_FILE_NAME).exists());
        Ok(())
    }

    #[test]
    fn app_data_root_swap_is_detected_and_cannot_redirect_commit() -> anyhow::Result<()> {
        let parent = tempfile::tempdir()?;
        let app_data = parent.path().join("app-data");
        fs::create_dir(&app_data)?;
        fs::set_permissions(&app_data, fs::Permissions::from_mode(0o700))?;

        let mut transaction = net(store(&app_data)?.begin())?;
        net(transaction.classify(candidate(42, 'a')?, 150))?;

        let detached = parent.path().join("detached-app-data");
        fs::rename(&app_data, &detached)?;
        fs::create_dir(&app_data)?;
        fs::set_permissions(&app_data, fs::Permissions::from_mode(0o700))?;

        assert_eq!(transaction.commit(150), Err(NetworkErrorCode::PolicySignatureInvalid));
        assert!(!app_data.join(NETWORKING_DIRECTORY_NAME).exists());
        assert!(detached.join(NETWORKING_DIRECTORY_NAME).exists());
        assert!(!detached.join(NETWORKING_DIRECTORY_NAME).join(RECORD_FILE_NAME).exists());
        Ok(())
    }
}
