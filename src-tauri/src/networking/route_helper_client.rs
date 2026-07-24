use std::{
    ffi::CString,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use super::{
    MihomoTunSnapshot, NetworkErrorCode, NetworkProfile, ProductionRouteBoundary, ProductionRouteDisposition,
    ProductionRouteRetirementReceipt, ProductionRouteRetirementResult, ROUTE_HELPER_PROTOCOL_VERSION, RouteHelperState,
    RouteHelperStatus, RouteLeaseOwner, RouteLeaseReference, TunnelDeviceFacts,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeReply {
    transport_status: i32,
    protocol_version: i32,
    state: i32,
    error_code: i32,
}

const DISCOVERY_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const DISCOVERY_INITIAL_BACKOFF: Duration = Duration::from_millis(25);
const DISCOVERY_MAX_BACKOFF: Duration = Duration::from_millis(200);
const DISCOVERY_MAX_ATTEMPTS: u16 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteHelperCallError {
    Terminal(NetworkErrorCode),
    Local(NetworkErrorCode),
}

impl RouteHelperCallError {
    const fn code(self) -> NetworkErrorCode {
        match self {
            Self::Terminal(error) | Self::Local(error) => error,
        }
    }

    const fn terminates_generation(self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

trait RouteHelperGeneration: Send {
    fn discover(&self) -> Result<RouteHelperStatus, RouteHelperCallError>;
    fn begin(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError>;
    fn recover(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError>;
    fn apply(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError>;
    fn rollback(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError>;
    fn heartbeat(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError>;
}

static NEXT_ROUTE_BOUNDARY_INCARNATION: AtomicU64 = AtomicU64::new(1);

/// Private construction capability for a route-boundary retirement receipt.
/// Sibling networking modules may name this type only so the receipt issuer
/// can accept it; they cannot construct a value or obtain the boundary's
/// retained capability.
pub(super) struct RouteRetirementIssuer {
    boundary_incarnation: u64,
}

impl RouteRetirementIssuer {
    pub(super) fn allocate() -> Result<Self, NetworkErrorCode> {
        NEXT_ROUTE_BOUNDARY_INCARNATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1))
            .map(|boundary_incarnation| Self { boundary_incarnation })
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)
    }

    pub(super) const fn boundary_incarnation(&self) -> u64 {
        self.boundary_incarnation
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn test_retirement_receipt(native_generation: u64) -> ProductionRouteRetirementReceipt {
    let issuer = RouteRetirementIssuer::allocate().expect("test route receipt issuer exhausted");
    ProductionRouteRetirementReceipt::issued(&issuer, native_generation)
}

#[derive(Default)]
struct RouteHelperCallTracker {
    in_flight: AtomicUsize,
}

impl RouteHelperCallTracker {
    fn enter(&self) -> Result<RouteHelperCallGuard<'_>, RouteHelperCallError> {
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| current.checked_add(1))
            .map_err(|_| RouteHelperCallError::Local(NetworkErrorCode::InvalidStateTransition))?;
        Ok(RouteHelperCallGuard { tracker: self })
    }

    fn is_idle(&self) -> bool {
        self.in_flight.load(Ordering::Acquire) == 0
    }
}

struct RouteHelperCallGuard<'a> {
    tracker: &'a RouteHelperCallTracker,
}

impl Drop for RouteHelperCallGuard<'_> {
    fn drop(&mut self) {
        let previous = self.tracker.in_flight.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

struct TrackedRouteHelperGeneration {
    inner: Box<dyn RouteHelperGeneration>,
    calls: Arc<RouteHelperCallTracker>,
}

impl TrackedRouteHelperGeneration {
    fn new(inner: Box<dyn RouteHelperGeneration>, calls: Arc<RouteHelperCallTracker>) -> Self {
        Self { inner, calls }
    }
}

impl RouteHelperGeneration for TrackedRouteHelperGeneration {
    fn discover(&self) -> Result<RouteHelperStatus, RouteHelperCallError> {
        let _call = self.calls.enter()?;
        self.inner.discover()
    }

    fn begin(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError> {
        let _call = self.calls.enter()?;
        self.inner.begin(owner)
    }

    fn recover(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError> {
        let _call = self.calls.enter()?;
        self.inner.recover(owner)
    }

    fn apply(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        let _call = self.calls.enter()?;
        self.inner.apply(reference)
    }

    fn rollback(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        let _call = self.calls.enter()?;
        self.inner.rollback(reference)
    }

    fn heartbeat(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        let _call = self.calls.enter()?;
        self.inner.heartbeat(reference)
    }
}

trait RouteHelperGenerationFactory: Send {
    fn create(&mut self) -> Result<Box<dyn RouteHelperGeneration>, NetworkErrorCode>;
}

#[derive(Clone, Copy)]
struct DiscoveryPolicy {
    total_timeout: Duration,
    initial_backoff: Duration,
    maximum_backoff: Duration,
    maximum_attempts: u16,
}

impl DiscoveryPolicy {
    const PRODUCTION: Self = Self {
        total_timeout: DISCOVERY_TOTAL_TIMEOUT,
        initial_backoff: DISCOVERY_INITIAL_BACKOFF,
        maximum_backoff: DISCOVERY_MAX_BACKOFF,
        maximum_attempts: DISCOVERY_MAX_ATTEMPTS,
    };
}

trait DiscoveryTimer {
    fn expired(&self) -> bool;
    fn wait(&mut self, delay: Duration) -> bool;
}

struct WallClockDiscoveryTimer {
    deadline: Instant,
}

impl WallClockDiscoveryTimer {
    fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
        }
    }
}

impl DiscoveryTimer for WallClockDiscoveryTimer {
    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn wait(&mut self, delay: Duration) -> bool {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(delay.min(remaining));
        !self.expired()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconciliationError {
    Deadline,
    Call(RouteHelperCallError),
    Status(NetworkErrorCode),
}

impl ReconciliationError {
    const fn code(self) -> NetworkErrorCode {
        match self {
            Self::Deadline => NetworkErrorCode::OperationTimedOut,
            Self::Call(error) => error.code(),
            Self::Status(error) => error,
        }
    }

    const fn terminates_generation(self) -> bool {
        matches!(self, Self::Call(error) if error.terminates_generation())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{c_char, c_void};

    use super::NativeReply;

    unsafe extern "C" {
        pub fn kyclash_route_helper_client_create() -> *mut c_void;
        pub fn kyclash_route_helper_client_destroy(client: *mut c_void);
        pub fn kyclash_route_helper_client_discover(client: *mut c_void) -> NativeReply;
        pub fn kyclash_route_helper_client_owner(
            client: *mut c_void,
            method: i32,
            version: u8,
            lease: *const c_char,
            operation: *const c_char,
            instance: *const c_char,
            interface_name: *const c_char,
            tunnel_operation: *const c_char,
            mtu: u16,
            revision: u64,
            has_ipv4: u8,
            has_ipv6: u8,
            mihomo_interfaces: *const *const c_char,
            mihomo_interface_count: usize,
            cidrs: *const *const c_char,
            cidr_count: usize,
        ) -> NativeReply;
        pub fn kyclash_route_helper_client_reference(
            client: *mut c_void,
            method: i32,
            version: u8,
            lease: *const c_char,
            operation: *const c_char,
        ) -> NativeReply;
    }
}

pub struct RouteHelperClient {
    native: usize,
    request_lock: Mutex<()>,
}

impl RouteHelperClient {
    pub fn connect() -> Result<Self, NetworkErrorCode> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: The fixed bridge creates one retained NSXPC client and returns ownership.
            let native = unsafe { platform::kyclash_route_helper_client_create() } as usize;
            if native == 0 {
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            Ok(Self {
                native,
                request_lock: Mutex::new(()),
            })
        }
        #[cfg(not(target_os = "macos"))]
        Err(NetworkErrorCode::SidecarUnavailable)
    }

    fn discover_call(&self) -> Result<RouteHelperStatus, RouteHelperCallError> {
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| RouteHelperCallError::Terminal(NetworkErrorCode::SidecarUnavailable))?;
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` owns a live bridge client until Drop and takes no caller data.
            native_status(
                unsafe { platform::kyclash_route_helper_client_discover(self.native as *mut _) },
                None,
            )
        }
        #[cfg(not(target_os = "macos"))]
        Err(RouteHelperCallError::Terminal(NetworkErrorCode::SidecarUnavailable))
    }

    fn begin_call(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError> {
        self.owner_request_call(0, owner)
    }

    fn recover_call(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError> {
        self.owner_request_call(1, owner)
    }

    fn apply_call(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        self.reference_request_call(0, reference)
    }

    fn rollback_call(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        self.reference_request_call(1, reference)
    }

    fn heartbeat_call(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        self.reference_request_call(2, reference)
    }

    /// Preserve the pre-generation public client surface for lab callers and
    /// external integration tests.  Generation management consumes the typed
    /// internal error so only the boundary decides whether a call is terminal.
    pub fn discover(&self) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.discover_call().map_err(RouteHelperCallError::code)
    }

    pub fn begin(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.begin_call(owner).map_err(RouteHelperCallError::code)
    }

    pub fn recover(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.recover_call(owner).map_err(RouteHelperCallError::code)
    }

    pub fn apply(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.apply_call(reference).map_err(RouteHelperCallError::code)
    }

    pub fn rollback(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.rollback_call(reference).map_err(RouteHelperCallError::code)
    }

    pub fn heartbeat(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.heartbeat_call(reference).map_err(RouteHelperCallError::code)
    }

    pub fn status(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, NetworkErrorCode> {
        self.reference_request_call(3, reference)
            .map_err(RouteHelperCallError::code)
    }

    fn owner_request_call(
        &self,
        method: i32,
        owner: &RouteLeaseOwner,
    ) -> Result<RouteHelperStatus, RouteHelperCallError> {
        owner.validate().map_err(RouteHelperCallError::Local)?;
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| RouteHelperCallError::Terminal(NetworkErrorCode::SidecarUnavailable))?;
        let lease = c_string(&owner.lease_id).map_err(RouteHelperCallError::Local)?;
        let operation = c_string(&owner.operation_id).map_err(RouteHelperCallError::Local)?;
        let instance = c_string(&owner.sidecar_instance_id).map_err(RouteHelperCallError::Local)?;
        let interface_name = c_string(&owner.tunnel.interface_name).map_err(RouteHelperCallError::Local)?;
        let tunnel_operation = c_string(&owner.tunnel.operation_id).map_err(RouteHelperCallError::Local)?;
        let cidrs = owner
            .private_cidrs
            .iter()
            .map(|value| c_string(value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(RouteHelperCallError::Local)?;
        let cidr_pointers = cidrs.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
        let mihomo_interfaces = owner
            .active_mihomo_tun_interfaces
            .iter()
            .map(|value| c_string(value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(RouteHelperCallError::Local)?;
        let mihomo_interface_pointers = mihomo_interfaces.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Every pointer references a validated CString retained for the entire
            // synchronous bridge call. The CIDR pointer/count pair exactly matches `cidrs`.
            native_status(
                unsafe {
                    platform::kyclash_route_helper_client_owner(
                        self.native as *mut _,
                        method,
                        owner.protocol_version,
                        lease.as_ptr(),
                        operation.as_ptr(),
                        instance.as_ptr(),
                        interface_name.as_ptr(),
                        tunnel_operation.as_ptr(),
                        owner.tunnel.mtu,
                        owner.profile_revision,
                        u8::from(owner.tunnel.has_ipv4),
                        u8::from(owner.tunnel.has_ipv6),
                        mihomo_interface_pointers.as_ptr(),
                        mihomo_interface_pointers.len(),
                        cidr_pointers.as_ptr(),
                        cidr_pointers.len(),
                    )
                },
                Some(owner.operation_id.clone()),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                method,
                lease,
                operation,
                instance,
                interface_name,
                tunnel_operation,
                mihomo_interface_pointers,
                cidr_pointers,
            );
            Err(RouteHelperCallError::Terminal(NetworkErrorCode::SidecarUnavailable))
        }
    }

    fn reference_request_call(
        &self,
        method: i32,
        reference: &RouteLeaseReference,
    ) -> Result<RouteHelperStatus, RouteHelperCallError> {
        reference.validate().map_err(RouteHelperCallError::Local)?;
        let _guard = self
            .request_lock
            .lock()
            .map_err(|_| RouteHelperCallError::Terminal(NetworkErrorCode::SidecarUnavailable))?;
        let lease = c_string(&reference.lease_id).map_err(RouteHelperCallError::Local)?;
        let operation = c_string(&reference.operation_id).map_err(RouteHelperCallError::Local)?;
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Both pointers reference validated CStrings retained for the entire
            // synchronous bridge call, and method is selected only by fixed Rust methods.
            native_status(
                unsafe {
                    platform::kyclash_route_helper_client_reference(
                        self.native as *mut _,
                        method,
                        reference.protocol_version,
                        lease.as_ptr(),
                        operation.as_ptr(),
                    )
                },
                Some(reference.operation_id.clone()),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (method, lease, operation);
            Err(RouteHelperCallError::Terminal(NetworkErrorCode::SidecarUnavailable))
        }
    }
}

impl RouteHelperGeneration for RouteHelperClient {
    fn discover(&self) -> Result<RouteHelperStatus, RouteHelperCallError> {
        Self::discover_call(self)
    }

    fn begin(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError> {
        Self::begin_call(self, owner)
    }

    fn recover(&self, owner: &RouteLeaseOwner) -> Result<RouteHelperStatus, RouteHelperCallError> {
        Self::recover_call(self, owner)
    }

    fn apply(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        Self::apply_call(self, reference)
    }

    fn rollback(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        Self::rollback_call(self, reference)
    }

    fn heartbeat(&self, reference: &RouteLeaseReference) -> Result<RouteHelperStatus, RouteHelperCallError> {
        Self::heartbeat_call(self, reference)
    }
}

struct NativeRouteHelperGenerationFactory;

impl RouteHelperGenerationFactory for NativeRouteHelperGenerationFactory {
    fn create(&mut self) -> Result<Box<dyn RouteHelperGeneration>, NetworkErrorCode> {
        RouteHelperClient::connect().map(|client| Box::new(client) as Box<dyn RouteHelperGeneration>)
    }
}

impl Drop for RouteHelperClient {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.native != 0 {
            // SAFETY: `native` was returned retained by create and is released exactly once.
            unsafe { platform::kyclash_route_helper_client_destroy(self.native as *mut _) };
            self.native = 0;
        }
    }
}

fn discover_authoritative_idle(
    client: &dyn RouteHelperGeneration,
    policy: DiscoveryPolicy,
) -> Result<(), ReconciliationError> {
    let mut timer = WallClockDiscoveryTimer::new(policy.total_timeout);
    discover_authoritative_idle_with_timer(client, policy, &mut timer)
}

fn discover_authoritative_idle_with_timer(
    client: &dyn RouteHelperGeneration,
    policy: DiscoveryPolicy,
    timer: &mut dyn DiscoveryTimer,
) -> Result<(), ReconciliationError> {
    let mut backoff = policy.initial_backoff;
    let mut attempts = 0_u16;
    loop {
        if timer.expired() || attempts >= policy.maximum_attempts {
            return Err(ReconciliationError::Deadline);
        }
        attempts += 1;
        match client.discover() {
            Ok(status) if is_typed_not_ready(&status) => {
                if attempts >= policy.maximum_attempts || !timer.wait(backoff) {
                    return Err(ReconciliationError::Deadline);
                }
                backoff = backoff.saturating_mul(2).min(policy.maximum_backoff);
            }
            Ok(status) => {
                if timer.expired() {
                    return Err(ReconciliationError::Deadline);
                }
                return require_authoritative_idle(&status).map_err(ReconciliationError::Status);
            }
            Err(error) => return Err(ReconciliationError::Call(error)),
        }
    }
}

pub struct XpcProductionRouteBoundary {
    client: Option<Box<dyn RouteHelperGeneration>>,
    factory: Box<dyn RouteHelperGenerationFactory>,
    calls: Arc<RouteHelperCallTracker>,
    native_generation: u64,
    retirement_issuer: RouteRetirementIssuer,
    discovery_policy: DiscoveryPolicy,
    active: Option<RouteLeaseReference>,
    active_owner: Option<RouteLeaseOwner>,
    recovery_required: bool,
    mutations_blocked: bool,
    reconciliation_error: Option<NetworkErrorCode>,
    retired: bool,
}

impl XpcProductionRouteBoundary {
    pub fn connect() -> Result<Self, NetworkErrorCode> {
        Self::connect_with_factory(
            Box::new(NativeRouteHelperGenerationFactory),
            DiscoveryPolicy::PRODUCTION,
        )
    }

    fn connect_with_factory(
        mut factory: Box<dyn RouteHelperGenerationFactory>,
        discovery_policy: DiscoveryPolicy,
    ) -> Result<Self, NetworkErrorCode> {
        let calls = Arc::new(RouteHelperCallTracker::default());
        let client: Box<dyn RouteHelperGeneration> =
            Box::new(TrackedRouteHelperGeneration::new(factory.create()?, Arc::clone(&calls)));
        // A fresh process does not possess the frozen owner envelope needed to
        // prove ownership of a durable journal left by an older process. It
        // must fail closed instead of synthesising an owner from new input.
        discover_authoritative_idle(client.as_ref(), discovery_policy).map_err(ReconciliationError::code)?;
        let retirement_issuer = RouteRetirementIssuer::allocate()?;
        Ok(Self {
            client: Some(client),
            factory,
            calls,
            native_generation: 1,
            retirement_issuer,
            discovery_policy,
            active: None,
            active_owner: None,
            recovery_required: false,
            mutations_blocked: false,
            reconciliation_error: None,
            retired: false,
        })
    }

    fn live_client(&self) -> Result<&dyn RouteHelperGeneration, NetworkErrorCode> {
        if self.retired {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        if self.mutations_blocked {
            return Err(self
                .reconciliation_error
                .unwrap_or(NetworkErrorCode::InvalidStateTransition));
        }
        self.client.as_deref().ok_or(NetworkErrorCode::SidecarUnavailable)
    }

    fn clear_frozen_owner(&mut self) {
        self.active = None;
        self.active_owner = None;
        self.recovery_required = false;
        self.mutations_blocked = false;
        self.reconciliation_error = None;
    }

    const fn freeze_without_replacement(&mut self, error: NetworkErrorCode) -> NetworkErrorCode {
        self.recovery_required = true;
        self.mutations_blocked = true;
        self.reconciliation_error = Some(error);
        error
    }

    fn reconcile_terminal_generation(&mut self, primary: NetworkErrorCode) -> NetworkErrorCode {
        self.recovery_required = true;
        self.mutations_blocked = true;
        self.reconciliation_error = Some(primary);

        // Destroy exactly the terminal native generation before constructing
        // its one replacement. No mutation is ever replayed on the replacement.
        drop(self.client.take());
        let fresh = match self.factory.create() {
            Ok(client) => client,
            Err(error) => {
                self.reconciliation_error = Some(error);
                return primary;
            }
        };
        let Some(native_generation) = self.native_generation.checked_add(1) else {
            self.reconciliation_error = Some(NetworkErrorCode::InvalidStateTransition);
            return primary;
        };
        self.native_generation = native_generation;
        self.client = Some(Box::new(TrackedRouteHelperGeneration::new(
            fresh,
            Arc::clone(&self.calls),
        )));
        let reconciliation = match self.client.as_deref() {
            Some(client) => discover_authoritative_idle(client, self.discovery_policy),
            None => Err(ReconciliationError::Call(RouteHelperCallError::Terminal(
                NetworkErrorCode::SidecarUnavailable,
            ))),
        };
        match reconciliation {
            Ok(()) => {
                self.clear_frozen_owner();
            }
            Err(error) => {
                self.reconciliation_error = Some(error.code());
                if error.terminates_generation() {
                    drop(self.client.take());
                }
            }
        }
        primary
    }

    fn handle_call_error(&mut self, error: RouteHelperCallError) -> NetworkErrorCode {
        if error.terminates_generation() {
            self.reconcile_terminal_generation(error.code())
        } else {
            // Local validation failures happen before an IPC message is sent.
            // They must not poison a live native generation or authorize a
            // replacement; the caller may retry with corrected input.
            error.code()
        }
    }

    fn rollback_after_helper_error(
        &mut self,
        reference: &RouteLeaseReference,
        primary: NetworkErrorCode,
    ) -> NetworkErrorCode {
        let rollback = match self.live_client() {
            Ok(client) => client.rollback(reference),
            Err(error) => {
                self.recovery_required = true;
                self.reconciliation_error = Some(error);
                return primary;
            }
        };
        match rollback {
            Ok(status) => {
                if is_typed_not_ready(&status) {
                    self.freeze_without_replacement(NetworkErrorCode::SidecarUnavailable);
                } else {
                    match require_helper_status(&status, RouteHelperState::Idle) {
                        Ok(()) => self.clear_frozen_owner(),
                        Err(error) => {
                            self.recovery_required = true;
                            self.reconciliation_error = Some(error);
                        }
                    }
                }
            }
            Err(error) if error.terminates_generation() => {
                self.reconcile_terminal_generation(primary);
            }
            Err(RouteHelperCallError::Local(_)) => {
                // No native request was sent, so retain the live generation
                // and preserve the original typed operation error.
            }
            Err(error) => {
                self.freeze_without_replacement(error.code());
            }
        }
        primary
    }

    fn recover_active(&mut self) -> Result<RouteHelperState, NetworkErrorCode> {
        let owner = self
            .active_owner
            .clone()
            .ok_or(NetworkErrorCode::InvalidStateTransition)?;
        let recovered = match self.live_client()?.recover(&owner) {
            Ok(status) => status,
            Err(error) => return Err(self.handle_call_error(error)),
        };
        if is_typed_not_ready(&recovered) {
            return Err(self.freeze_without_replacement(NetworkErrorCode::SidecarUnavailable));
        }
        if let Some(error) = recovered.error_code {
            return Err(error);
        }
        match recovered.state {
            RouteHelperState::Prepared | RouteHelperState::Applied => {
                self.recovery_required = false;
                Ok(recovered.state)
            }
            _ => Err(NetworkErrorCode::InvalidStateTransition),
        }
    }
}

impl ProductionRouteBoundary for XpcProductionRouteBoundary {
    fn disposition(&self) -> ProductionRouteDisposition {
        if self.retired {
            return ProductionRouteDisposition::Retired;
        }
        if !self.calls.is_idle() {
            return ProductionRouteDisposition::Busy;
        }
        if self.recovery_required
            || self.mutations_blocked
            || self.reconciliation_error.is_some()
            || self.client.is_none()
        {
            return ProductionRouteDisposition::RecoveryOnly;
        }
        match (&self.active, &self.active_owner) {
            (None, None) => ProductionRouteDisposition::Reusable,
            (Some(_), Some(_)) => ProductionRouteDisposition::Busy,
            _ => ProductionRouteDisposition::RecoveryOnly,
        }
    }

    fn try_retire(&mut self) -> ProductionRouteRetirementResult {
        match self.disposition() {
            ProductionRouteDisposition::Busy => ProductionRouteRetirementResult::Busy,
            ProductionRouteDisposition::RecoveryOnly => ProductionRouteRetirementResult::RecoveryOnly,
            ProductionRouteDisposition::Retired => ProductionRouteRetirementResult::AlreadyRetired,
            ProductionRouteDisposition::Reusable => {
                let Some(client) = self.client.take() else {
                    return ProductionRouteRetirementResult::RecoveryOnly;
                };
                // XPC-B makes destroy terminalize the native generation, wake
                // every waiter exactly once, and render every late callback
                // inert. The call tracker and empty owner/ref state above are
                // the positive Rust-side prerequisites for that close.
                drop(client);
                self.retired = true;
                ProductionRouteRetirementResult::Retired(ProductionRouteRetirementReceipt::issued(
                    &self.retirement_issuer,
                    self.native_generation,
                ))
            }
        }
    }

    fn apply(
        &mut self,
        profile: &NetworkProfile,
        operation_id: &str,
        tunnel: &TunnelDeviceFacts,
        profile_revision: u64,
        mihomo: &MihomoTunSnapshot,
    ) -> Result<(), NetworkErrorCode> {
        self.live_client()?;
        let owner = RouteLeaseOwner {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            lease_id: operation_id.to_owned(),
            operation_id: operation_id.to_owned(),
            sidecar_instance_id: tunnel.instance_id.clone(),
            profile_revision,
            tunnel: tunnel.clone(),
            active_mihomo_tun_interfaces: mihomo.interfaces().to_vec(),
            private_cidrs: profile.site.private_cidrs.clone(),
        };
        mihomo.validate_for(&tunnel.interface_name)?;
        owner.validate()?;
        let reference = RouteLeaseReference {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            lease_id: owner.lease_id.clone(),
            operation_id: owner.operation_id.clone(),
        };

        if self.recovery_required {
            if self.active.as_ref() != Some(&reference) || self.active_owner.as_ref() != Some(&owner) {
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            match self.recover_active()? {
                RouteHelperState::Applied => {
                    return Ok(());
                }
                RouteHelperState::Prepared => {}
                _ => return Err(NetworkErrorCode::InvalidStateTransition),
            }
        } else {
            if self.active.is_some() || self.active_owner.is_some() {
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            self.active = Some(reference.clone());
            self.active_owner = Some(owner.clone());
            let begin = match self.live_client()?.begin(&owner) {
                Ok(status) => status,
                Err(RouteHelperCallError::Local(error)) => {
                    // The owner was validated before this call and no native
                    // mutation was sent when local conversion fails. Drop the
                    // staged Rust-only owner and leave the generation live.
                    self.active = None;
                    self.active_owner = None;
                    return Err(error);
                }
                Err(error) => {
                    return Err(self.handle_call_error(error));
                }
            };
            if is_typed_not_ready(&begin) {
                return Err(self.freeze_without_replacement(NetworkErrorCode::SidecarUnavailable));
            }
            if let Err(error) = require_helper_status(&begin, RouteHelperState::Prepared) {
                return Err(self.rollback_after_helper_error(&reference, error));
            }
        }
        let applied = match self.live_client()?.apply(&reference) {
            Ok(status) => status,
            Err(error) => {
                return Err(self.handle_call_error(error));
            }
        };
        if is_typed_not_ready(&applied) {
            return Err(self.freeze_without_replacement(NetworkErrorCode::SidecarUnavailable));
        }
        if let Err(error) = require_helper_status(&applied, RouteHelperState::Applied) {
            return Err(self.rollback_after_helper_error(&reference, error));
        }
        Ok(())
    }

    fn heartbeat(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.live_client()?;
        if self.recovery_required {
            match self.recover_active()? {
                RouteHelperState::Applied => {}
                RouteHelperState::Prepared => return Err(NetworkErrorCode::InvalidStateTransition),
                _ => return Err(NetworkErrorCode::InvalidStateTransition),
            }
        }
        let reference = self
            .active
            .as_ref()
            .filter(|reference| reference.operation_id == operation_id)
            .cloned()
            .ok_or(NetworkErrorCode::InvalidStateTransition)?;
        match self.live_client()?.heartbeat(&reference) {
            Ok(status) => {
                if is_typed_not_ready(&status) {
                    return Err(self.freeze_without_replacement(NetworkErrorCode::SidecarUnavailable));
                }
                let result = require_helper_status(&status, RouteHelperState::Applied);
                if result.is_err() {
                    self.recovery_required = true;
                }
                result
            }
            Err(error) => Err(self.handle_call_error(error)),
        }
    }

    fn rollback(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.live_client()?;
        let Some(reference) = self.active.clone() else {
            return Ok(());
        };
        if reference.operation_id != operation_id {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        if self.recovery_required {
            // Recovery authenticates the frozen owner before a rollback retry.
            self.recover_active()?;
        }
        let status = match self.live_client()?.rollback(&reference) {
            Ok(status) => status,
            Err(error) => {
                return Err(self.handle_call_error(error));
            }
        };
        if is_typed_not_ready(&status) {
            return Err(self.freeze_without_replacement(NetworkErrorCode::SidecarUnavailable));
        }
        if let Err(error) = require_helper_status(&status, RouteHelperState::Idle) {
            self.recovery_required = true;
            return Err(error);
        }
        self.active = None;
        self.active_owner = None;
        self.recovery_required = false;
        Ok(())
    }
}

impl Drop for XpcProductionRouteBoundary {
    fn drop(&mut self) {
        // Drop remains best-effort emergency cleanup only. It deliberately
        // cannot mint a retirement receipt and therefore is not positive
        // absence evidence for service replacement.
        if !self.mutations_blocked
            && !self.retired
            && let (Some(client), Some(reference)) = (self.client.as_deref(), self.active.as_ref())
        {
            let _ = client.rollback(reference);
        }
    }
}

fn c_string(value: &str) -> Result<CString, NetworkErrorCode> {
    CString::new(value).map_err(|_| NetworkErrorCode::InvalidConfiguration)
}

fn native_status(reply: NativeReply, operation_id: Option<String>) -> Result<RouteHelperStatus, RouteHelperCallError> {
    match reply.transport_status {
        0 => {}
        1 => return Err(RouteHelperCallError::Terminal(NetworkErrorCode::OperationTimedOut)),
        2..=4 | 6 => return Err(RouteHelperCallError::Terminal(NetworkErrorCode::SidecarUnavailable)),
        5 => {
            return Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion,
            ));
        }
        7 => return Err(RouteHelperCallError::Local(NetworkErrorCode::InvalidConfiguration)),
        _ => {
            return Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion,
            ));
        }
    }
    if reply.protocol_version != i32::from(ROUTE_HELPER_PROTOCOL_VERSION) {
        return Err(RouteHelperCallError::Terminal(
            NetworkErrorCode::UnsupportedProtocolVersion,
        ));
    }
    let state = match reply.state {
        0 => RouteHelperState::Idle,
        1 => RouteHelperState::Prepared,
        2 => RouteHelperState::Applied,
        3 => RouteHelperState::RollingBack,
        4 => RouteHelperState::FailedClosed,
        _ => {
            return Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion,
            ));
        }
    };
    let error_code = match reply.error_code {
        0 => None,
        1 => Some(NetworkErrorCode::SidecarUnavailable),
        2 => Some(NetworkErrorCode::InvalidConfiguration),
        3 => Some(NetworkErrorCode::PermissionDenied),
        4 => Some(NetworkErrorCode::RouteJournalUnavailable),
        5 => Some(NetworkErrorCode::PermissionDenied),
        6..=7 => Some(NetworkErrorCode::RouteRollbackFailed),
        8 => Some(NetworkErrorCode::RouteJournalCorrupted),
        9 => Some(NetworkErrorCode::RouteConflict),
        _ => {
            return Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion,
            ));
        }
    };
    let status = RouteHelperStatus {
        protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
        state,
        operation_id,
        error_code,
    };
    status.validate().map_err(RouteHelperCallError::Terminal)?;
    Ok(status)
}

fn is_typed_not_ready(status: &RouteHelperStatus) -> bool {
    status.protocol_version == ROUTE_HELPER_PROTOCOL_VERSION
        && status.state == RouteHelperState::FailedClosed
        && status.operation_id.is_none()
        && status.error_code == Some(NetworkErrorCode::SidecarUnavailable)
}

fn require_helper_status(status: &RouteHelperStatus, expected: RouteHelperState) -> Result<(), NetworkErrorCode> {
    if let Some(error) = status.error_code {
        return Err(error);
    }
    if status.protocol_version != ROUTE_HELPER_PROTOCOL_VERSION || status.state != expected {
        return Err(NetworkErrorCode::InvalidStateTransition);
    }
    Ok(())
}

fn require_authoritative_idle(status: &RouteHelperStatus) -> Result<(), NetworkErrorCode> {
    if status.operation_id.is_some() {
        return Err(NetworkErrorCode::InvalidStateTransition);
    }
    require_helper_status(status, RouteHelperState::Idle)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    type MockReply = Result<RouteHelperStatus, RouteHelperCallError>;

    #[derive(Default)]
    struct MockGenerationCounts {
        discover: AtomicUsize,
        begin: AtomicUsize,
        recover: AtomicUsize,
        apply: AtomicUsize,
        rollback: AtomicUsize,
        heartbeat: AtomicUsize,
        drops: AtomicUsize,
    }

    struct MockGenerationState {
        counts: MockGenerationCounts,
        discover: Mutex<VecDeque<MockReply>>,
        begin: Mutex<VecDeque<MockReply>>,
        recover: Mutex<VecDeque<MockReply>>,
        apply: Mutex<VecDeque<MockReply>>,
        rollback: Mutex<VecDeque<MockReply>>,
        heartbeat: Mutex<VecDeque<MockReply>>,
    }

    impl MockGenerationState {
        fn scripted(discover: Vec<MockReply>, begin: Vec<MockReply>, apply: Vec<MockReply>) -> Arc<Self> {
            Arc::new(Self {
                counts: MockGenerationCounts::default(),
                discover: Mutex::new(discover.into()),
                begin: Mutex::new(begin.into()),
                recover: Mutex::new(VecDeque::new()),
                apply: Mutex::new(apply.into()),
                rollback: Mutex::new(VecDeque::new()),
                heartbeat: Mutex::new(VecDeque::new()),
            })
        }

        fn next(queue: &Mutex<VecDeque<MockReply>>) -> MockReply {
            let Ok(mut queue) = queue.lock() else {
                return Err(RouteHelperCallError::Local(NetworkErrorCode::SidecarUnavailable));
            };
            queue.pop_front().unwrap_or(Err(RouteHelperCallError::Local(
                NetworkErrorCode::InvalidStateTransition,
            )))
        }
    }

    struct MockGeneration {
        state: Arc<MockGenerationState>,
    }

    impl RouteHelperGeneration for MockGeneration {
        fn discover(&self) -> MockReply {
            self.state.counts.discover.fetch_add(1, Ordering::SeqCst);
            MockGenerationState::next(&self.state.discover)
        }

        fn begin(&self, _owner: &RouteLeaseOwner) -> MockReply {
            self.state.counts.begin.fetch_add(1, Ordering::SeqCst);
            MockGenerationState::next(&self.state.begin)
        }

        fn recover(&self, _owner: &RouteLeaseOwner) -> MockReply {
            self.state.counts.recover.fetch_add(1, Ordering::SeqCst);
            MockGenerationState::next(&self.state.recover)
        }

        fn apply(&self, _reference: &RouteLeaseReference) -> MockReply {
            self.state.counts.apply.fetch_add(1, Ordering::SeqCst);
            MockGenerationState::next(&self.state.apply)
        }

        fn rollback(&self, _reference: &RouteLeaseReference) -> MockReply {
            self.state.counts.rollback.fetch_add(1, Ordering::SeqCst);
            MockGenerationState::next(&self.state.rollback)
        }

        fn heartbeat(&self, _reference: &RouteLeaseReference) -> MockReply {
            self.state.counts.heartbeat.fetch_add(1, Ordering::SeqCst);
            MockGenerationState::next(&self.state.heartbeat)
        }
    }

    impl Drop for MockGeneration {
        fn drop(&mut self) {
            self.state.counts.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockFactory {
        generations: VecDeque<Arc<MockGenerationState>>,
        creates: Arc<AtomicUsize>,
    }

    impl MockFactory {
        fn new(generations: Vec<Arc<MockGenerationState>>, creates: Arc<AtomicUsize>) -> Self {
            Self {
                generations: generations.into(),
                creates,
            }
        }
    }

    impl RouteHelperGenerationFactory for MockFactory {
        fn create(&mut self) -> Result<Box<dyn RouteHelperGeneration>, NetworkErrorCode> {
            self.creates.fetch_add(1, Ordering::SeqCst);
            self.generations
                .pop_front()
                .map(|state| Box::new(MockGeneration { state }) as Box<dyn RouteHelperGeneration>)
                .ok_or(NetworkErrorCode::SidecarUnavailable)
        }
    }

    struct RecordingTimer {
        waits: Vec<Duration>,
    }

    impl DiscoveryTimer for RecordingTimer {
        fn expired(&self) -> bool {
            false
        }

        fn wait(&mut self, delay: Duration) -> bool {
            self.waits.push(delay);
            true
        }
    }

    fn status(
        state: RouteHelperState,
        operation_id: Option<&str>,
        error_code: Option<NetworkErrorCode>,
    ) -> RouteHelperStatus {
        RouteHelperStatus {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            state,
            operation_id: operation_id.map(str::to_owned),
            error_code,
        }
    }

    fn idle() -> RouteHelperStatus {
        status(RouteHelperState::Idle, None, None)
    }

    fn not_ready() -> RouteHelperStatus {
        status(
            RouteHelperState::FailedClosed,
            None,
            Some(NetworkErrorCode::SidecarUnavailable),
        )
    }

    fn prepared(operation_id: &str) -> RouteHelperStatus {
        status(RouteHelperState::Prepared, Some(operation_id), None)
    }

    fn applied(operation_id: &str) -> RouteHelperStatus {
        status(RouteHelperState::Applied, Some(operation_id), None)
    }

    fn test_policy(maximum_attempts: u16) -> DiscoveryPolicy {
        DiscoveryPolicy {
            total_timeout: Duration::from_secs(1),
            initial_backoff: Duration::ZERO,
            maximum_backoff: Duration::ZERO,
            maximum_attempts,
        }
    }

    fn test_profile() -> Option<NetworkProfile> {
        serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json")).ok()
    }

    fn test_tunnel(operation_id: &str) -> TunnelDeviceFacts {
        TunnelDeviceFacts {
            interface_name: "utun42".into(),
            mtu: 1420,
            has_ipv4: true,
            has_ipv6: true,
            instance_id: "instance.test".into(),
            operation_id: format!("{operation_id}.prepare"),
        }
    }

    fn assert_no_mutation_calls(state: &MockGenerationState) {
        assert_eq!(state.counts.begin.load(Ordering::SeqCst), 0);
        assert_eq!(state.counts.recover.load(Ordering::SeqCst), 0);
        assert_eq!(state.counts.apply.load(Ordering::SeqCst), 0);
        assert_eq!(state.counts.rollback.load(Ordering::SeqCst), 0);
        assert_eq!(state.counts.heartbeat.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_reply_mapping_fails_closed_on_unknown_values() {
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    protocol_version: i32::from(ROUTE_HELPER_PROTOCOL_VERSION),
                    state: 99,
                    error_code: 0,
                },
                None,
            ),
            Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion
            ))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    protocol_version: 1,
                    state: 0,
                    error_code: 0,
                },
                None,
            ),
            Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion
            ))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: -1,
                    protocol_version: i32::from(ROUTE_HELPER_PROTOCOL_VERSION),
                    state: 0,
                    error_code: 0,
                },
                None,
            ),
            Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion
            ))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 1,
                    protocol_version: -1,
                    state: -1,
                    error_code: -1,
                },
                None,
            ),
            Err(RouteHelperCallError::Terminal(NetworkErrorCode::OperationTimedOut))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 7,
                    protocol_version: -1,
                    state: -1,
                    error_code: -1,
                },
                None,
            ),
            Err(RouteHelperCallError::Local(NetworkErrorCode::InvalidConfiguration))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    protocol_version: i32::from(ROUTE_HELPER_PROTOCOL_VERSION),
                    state: 4,
                    error_code: 8,
                },
                None,
            )
            .map(|status| status.error_code),
            Ok(Some(NetworkErrorCode::RouteJournalCorrupted))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    protocol_version: i32::from(ROUTE_HELPER_PROTOCOL_VERSION),
                    state: 4,
                    error_code: 9,
                },
                None,
            )
            .map(|status| status.error_code),
            Ok(Some(NetworkErrorCode::RouteConflict))
        );
        assert_eq!(
            native_status(
                NativeReply {
                    transport_status: 0,
                    protocol_version: i32::from(ROUTE_HELPER_PROTOCOL_VERSION),
                    state: 4,
                    error_code: 99,
                },
                None,
            ),
            Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::UnsupportedProtocolVersion
            ))
        );
    }

    #[test]
    fn typed_not_ready_is_only_the_read_only_discover_shape() {
        let discover = status(
            RouteHelperState::FailedClosed,
            None,
            Some(NetworkErrorCode::SidecarUnavailable),
        );
        assert!(is_typed_not_ready(&discover));
        assert!(!is_typed_not_ready(&RouteHelperStatus {
            operation_id: Some("operation.test".into()),
            ..discover
        }));
        assert!(!is_typed_not_ready(&RouteHelperStatus {
            state: RouteHelperState::Idle,
            ..discover
        }));
    }

    #[test]
    fn authoritative_idle_cannot_claim_an_operation_owner() {
        assert_eq!(require_authoritative_idle(&idle()), Ok(()));
        assert_eq!(
            require_authoritative_idle(&status(RouteHelperState::Idle, Some("operation.test"), None)),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
    }

    #[test]
    fn initial_discovery_retries_not_ready_on_one_generation() {
        let generation = MockGenerationState::scripted(vec![Ok(not_ready()), Ok(idle())], vec![], vec![]);
        let creates = Arc::new(AtomicUsize::new(0));
        {
            let result = XpcProductionRouteBoundary::connect_with_factory(
                Box::new(MockFactory::new(vec![Arc::clone(&generation)], Arc::clone(&creates))),
                test_policy(3),
            );
            assert!(result.is_ok());
            let Ok(boundary) = result else {
                return;
            };
            assert_eq!(creates.load(Ordering::SeqCst), 1);
            assert_eq!(generation.counts.discover.load(Ordering::SeqCst), 2);
            assert!(!boundary.mutations_blocked);
        }
        assert_eq!(generation.counts.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn idle_generation_retires_once_and_every_old_boundary_mutation_fails_closed() {
        let generation = MockGenerationState::scripted(vec![Ok(idle())], vec![], vec![]);
        let creates = Arc::new(AtomicUsize::new(0));
        let result = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(vec![Arc::clone(&generation)], Arc::clone(&creates))),
            test_policy(1),
        );
        assert!(result.is_ok());
        let Ok(mut boundary) = result else {
            return;
        };
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Reusable);
        let receipt = boundary.try_retire();
        assert!(
            matches!(&receipt, ProductionRouteRetirementResult::Retired(_)),
            "idle native generation did not produce a retirement receipt"
        );
        let ProductionRouteRetirementResult::Retired(receipt) = receipt else {
            return;
        };
        assert_eq!(receipt.native_generation(), 1);
        assert_eq!(generation.counts.drops.load(Ordering::SeqCst), 1);
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Retired);
        assert_eq!(boundary.try_retire(), ProductionRouteRetirementResult::AlreadyRetired);

        let Some(profile) = test_profile() else {
            return;
        };
        let operation = "operation.retired";
        assert_eq!(
            boundary.apply(
                &profile,
                operation,
                &test_tunnel(operation),
                42,
                &MihomoTunSnapshot::inactive(),
            ),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        assert_eq!(
            boundary.heartbeat(operation),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        assert_eq!(
            boundary.rollback(operation),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        assert_eq!(creates.load(Ordering::SeqCst), 1);
        assert_no_mutation_calls(&generation);
    }

    #[test]
    fn separate_boundaries_issue_distinct_incarnations_even_at_the_same_native_generation() {
        let first_generation = MockGenerationState::scripted(vec![Ok(idle())], vec![], vec![]);
        let second_generation = MockGenerationState::scripted(vec![Ok(idle())], vec![], vec![]);
        let first_creates = Arc::new(AtomicUsize::new(0));
        let second_creates = Arc::new(AtomicUsize::new(0));
        let first = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(
                vec![Arc::clone(&first_generation)],
                Arc::clone(&first_creates),
            )),
            test_policy(1),
        );
        let second = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(
                vec![Arc::clone(&second_generation)],
                Arc::clone(&second_creates),
            )),
            test_policy(1),
        );
        assert!(first.is_ok());
        assert!(second.is_ok());
        let Ok(mut first) = first else {
            return;
        };
        let Ok(mut second) = second else {
            return;
        };
        let first_receipt = first.try_retire();
        let second_receipt = second.try_retire();
        assert!(matches!(&first_receipt, ProductionRouteRetirementResult::Retired(_)));
        assert!(matches!(&second_receipt, ProductionRouteRetirementResult::Retired(_)));
        let ProductionRouteRetirementResult::Retired(first_receipt) = first_receipt else {
            return;
        };
        let ProductionRouteRetirementResult::Retired(second_receipt) = second_receipt else {
            return;
        };
        assert_ne!(
            first_receipt.boundary_incarnation(),
            second_receipt.boundary_incarnation()
        );
        assert_eq!(first_receipt.native_generation(), 1);
        assert_eq!(second_receipt.native_generation(), 1);
        assert_eq!(first_creates.load(Ordering::SeqCst), 1);
        assert_eq!(second_creates.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn in_flight_generation_call_makes_retirement_busy_until_the_call_drains() {
        let generation = MockGenerationState::scripted(vec![Ok(idle())], vec![], vec![]);
        let creates = Arc::new(AtomicUsize::new(0));
        let result = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(vec![Arc::clone(&generation)], Arc::clone(&creates))),
            test_policy(1),
        );
        assert!(result.is_ok());
        let Ok(mut boundary) = result else {
            return;
        };
        let calls = Arc::clone(&boundary.calls);
        let call = calls.enter();
        assert!(call.is_ok());
        let Ok(call) = call else {
            return;
        };
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Busy);
        assert_eq!(boundary.try_retire(), ProductionRouteRetirementResult::Busy);
        assert_eq!(generation.counts.drops.load(Ordering::SeqCst), 0);
        drop(call);
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Reusable);
        assert!(matches!(
            boundary.try_retire(),
            ProductionRouteRetirementResult::Retired(_)
        ));
        assert_eq!(generation.counts.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn active_owner_is_busy_and_unresolved_or_mismatched_state_is_recovery_only() {
        let operation = "operation.active";
        let generation = MockGenerationState::scripted(
            vec![Ok(idle())],
            vec![Ok(prepared(operation))],
            vec![Ok(applied(operation))],
        );
        let creates = Arc::new(AtomicUsize::new(0));
        let result = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(vec![Arc::clone(&generation)], Arc::clone(&creates))),
            test_policy(1),
        );
        assert!(result.is_ok());
        let Ok(mut boundary) = result else {
            return;
        };
        let Some(profile) = test_profile() else {
            return;
        };
        assert_eq!(
            boundary.apply(
                &profile,
                operation,
                &test_tunnel(operation),
                42,
                &MihomoTunSnapshot::inactive(),
            ),
            Ok(())
        );
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Busy);
        assert_eq!(boundary.try_retire(), ProductionRouteRetirementResult::Busy);
        assert_eq!(generation.counts.drops.load(Ordering::SeqCst), 0);

        boundary.recovery_required = true;
        boundary.mutations_blocked = true;
        boundary.reconciliation_error = Some(NetworkErrorCode::RouteRollbackFailed);
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::RecoveryOnly);
        assert_eq!(boundary.try_retire(), ProductionRouteRetirementResult::RecoveryOnly);
        assert_eq!(generation.counts.drops.load(Ordering::SeqCst), 0);

        boundary.recovery_required = false;
        boundary.mutations_blocked = false;
        boundary.reconciliation_error = None;
        boundary.active_owner = None;
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::RecoveryOnly);
        assert_eq!(boundary.try_retire(), ProductionRouteRetirementResult::RecoveryOnly);
    }

    #[test]
    fn discovery_backoff_and_attempt_count_are_bounded() {
        let generation =
            MockGenerationState::scripted(vec![Ok(not_ready()), Ok(not_ready()), Ok(not_ready())], vec![], vec![]);
        let client = MockGeneration {
            state: Arc::clone(&generation),
        };
        let policy = DiscoveryPolicy {
            total_timeout: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(5),
            maximum_backoff: Duration::from_millis(20),
            maximum_attempts: 3,
        };
        let mut timer = RecordingTimer { waits: Vec::new() };
        assert_eq!(
            discover_authoritative_idle_with_timer(&client, policy, &mut timer),
            Err(ReconciliationError::Deadline)
        );
        assert_eq!(generation.counts.discover.load(Ordering::SeqCst), 3);
        assert_eq!(timer.waits, vec![Duration::from_millis(5), Duration::from_millis(10)]);
    }

    #[test]
    fn initial_terminal_discovery_never_materializes_a_replacement() {
        let initial = MockGenerationState::scripted(
            vec![Err(RouteHelperCallError::Terminal(NetworkErrorCode::OperationTimedOut))],
            vec![],
            vec![],
        );
        let unused = MockGenerationState::scripted(vec![Ok(idle())], vec![], vec![]);
        let creates = Arc::new(AtomicUsize::new(0));
        let result = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(
                vec![Arc::clone(&initial), Arc::clone(&unused)],
                Arc::clone(&creates),
            )),
            test_policy(3),
        );
        assert_eq!(result.err(), Some(NetworkErrorCode::OperationTimedOut));
        assert_eq!(creates.load(Ordering::SeqCst), 1);
        assert_eq!(initial.counts.drops.load(Ordering::SeqCst), 1);
        assert_eq!(unused.counts.discover.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mutating_transport_failure_reconciles_once_without_replay() {
        let operation = "operation.test";
        let initial = MockGenerationState::scripted(
            vec![Ok(idle())],
            vec![Err(RouteHelperCallError::Terminal(NetworkErrorCode::OperationTimedOut))],
            vec![],
        );
        let fresh = MockGenerationState::scripted(vec![Ok(not_ready()), Ok(idle())], vec![], vec![]);
        let creates = Arc::new(AtomicUsize::new(0));
        let result = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(
                vec![Arc::clone(&initial), Arc::clone(&fresh)],
                Arc::clone(&creates),
            )),
            test_policy(3),
        );
        assert!(result.is_ok());
        let Ok(mut boundary) = result else {
            return;
        };
        let profile = test_profile();
        assert!(profile.is_some());
        let Some(profile) = profile else {
            return;
        };

        assert_eq!(
            boundary.apply(
                &profile,
                operation,
                &test_tunnel(operation),
                42,
                &MihomoTunSnapshot::inactive(),
            ),
            Err(NetworkErrorCode::OperationTimedOut)
        );
        assert_eq!(creates.load(Ordering::SeqCst), 2);
        assert_eq!(initial.counts.begin.load(Ordering::SeqCst), 1);
        assert_eq!(initial.counts.rollback.load(Ordering::SeqCst), 0);
        assert_eq!(initial.counts.drops.load(Ordering::SeqCst), 1);
        assert_eq!(fresh.counts.discover.load(Ordering::SeqCst), 2);
        assert_no_mutation_calls(&fresh);
        assert!(boundary.active.is_none());
        assert!(boundary.active_owner.is_none());
        assert!(!boundary.recovery_required);
        assert!(!boundary.mutations_blocked);
        assert_eq!(boundary.disposition(), ProductionRouteDisposition::Reusable);
        let retirement = boundary.try_retire();
        assert!(
            matches!(&retirement, ProductionRouteRetirementResult::Retired(_)),
            "reconciled fresh generation did not retire"
        );
        let ProductionRouteRetirementResult::Retired(receipt) = retirement else {
            return;
        };
        assert_eq!(receipt.native_generation(), 2);
        assert_eq!(fresh.counts.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fresh_transport_failure_retains_frozen_owner_and_cannot_recurse() {
        let operation = "operation.test";
        let initial = MockGenerationState::scripted(
            vec![Ok(idle())],
            vec![Ok(prepared(operation))],
            vec![Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::SidecarUnavailable,
            ))],
        );
        let fresh = MockGenerationState::scripted(
            vec![Err(RouteHelperCallError::Terminal(NetworkErrorCode::OperationTimedOut))],
            vec![],
            vec![],
        );
        let creates = Arc::new(AtomicUsize::new(0));
        let result = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(
                vec![Arc::clone(&initial), Arc::clone(&fresh)],
                Arc::clone(&creates),
            )),
            test_policy(3),
        );
        assert!(result.is_ok());
        let Ok(mut boundary) = result else {
            return;
        };
        let profile = test_profile();
        assert!(profile.is_some());
        let Some(profile) = profile else {
            return;
        };

        assert_eq!(
            boundary.apply(
                &profile,
                operation,
                &test_tunnel(operation),
                42,
                &MihomoTunSnapshot::inactive(),
            ),
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert_eq!(
            boundary
                .active
                .as_ref()
                .map(|reference| reference.operation_id.as_str()),
            Some(operation)
        );
        assert_eq!(
            boundary.active_owner.as_ref().map(|owner| owner.operation_id.as_str()),
            Some(operation)
        );
        assert!(boundary.recovery_required);
        assert!(boundary.mutations_blocked);
        assert_eq!(boundary.reconciliation_error, Some(NetworkErrorCode::OperationTimedOut));
        assert!(boundary.client.is_none());
        assert_eq!(boundary.heartbeat(operation), Err(NetworkErrorCode::OperationTimedOut));
        assert_eq!(boundary.rollback(operation), Err(NetworkErrorCode::OperationTimedOut));
        assert_eq!(creates.load(Ordering::SeqCst), 2);
        assert_eq!(initial.counts.rollback.load(Ordering::SeqCst), 0);
        assert_eq!(fresh.counts.discover.load(Ordering::SeqCst), 1);
        assert_no_mutation_calls(&fresh);
        assert_eq!(fresh.counts.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fresh_discovery_deadline_retains_owner_on_the_same_generation() {
        let operation = "operation.test";
        let initial = MockGenerationState::scripted(
            vec![Ok(idle())],
            vec![Ok(prepared(operation))],
            vec![Err(RouteHelperCallError::Terminal(
                NetworkErrorCode::SidecarUnavailable,
            ))],
        );
        let fresh = MockGenerationState::scripted(vec![Ok(not_ready()), Ok(not_ready())], vec![], vec![]);
        let creates = Arc::new(AtomicUsize::new(0));
        let result = XpcProductionRouteBoundary::connect_with_factory(
            Box::new(MockFactory::new(
                vec![Arc::clone(&initial), Arc::clone(&fresh)],
                Arc::clone(&creates),
            )),
            test_policy(2),
        );
        assert!(result.is_ok());
        let Ok(mut boundary) = result else {
            return;
        };
        let profile = test_profile();
        assert!(profile.is_some());
        let Some(profile) = profile else {
            return;
        };

        assert_eq!(
            boundary.apply(
                &profile,
                operation,
                &test_tunnel(operation),
                42,
                &MihomoTunSnapshot::inactive(),
            ),
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert!(boundary.client.is_some());
        assert!(boundary.active.is_some());
        assert!(boundary.active_owner.is_some());
        assert!(boundary.mutations_blocked);
        assert_eq!(boundary.reconciliation_error, Some(NetworkErrorCode::OperationTimedOut));
        assert_eq!(boundary.rollback(operation), Err(NetworkErrorCode::OperationTimedOut));
        assert_eq!(creates.load(Ordering::SeqCst), 2);
        assert_eq!(fresh.counts.discover.load(Ordering::SeqCst), 2);
        assert_no_mutation_calls(&fresh);
    }

    #[test]
    fn fresh_non_idle_or_recovery_required_reply_fails_closed_without_retry() {
        for (fresh_reply, expected) in [
            (
                Ok(status(RouteHelperState::Prepared, Some("operation.other"), None)),
                NetworkErrorCode::InvalidStateTransition,
            ),
            (
                Ok(status(
                    RouteHelperState::FailedClosed,
                    None,
                    Some(NetworkErrorCode::RouteRollbackFailed),
                )),
                NetworkErrorCode::RouteRollbackFailed,
            ),
        ] {
            let operation = "operation.test";
            let initial = MockGenerationState::scripted(
                vec![Ok(idle())],
                vec![Ok(prepared(operation))],
                vec![Err(RouteHelperCallError::Terminal(
                    NetworkErrorCode::SidecarUnavailable,
                ))],
            );
            let fresh = MockGenerationState::scripted(vec![fresh_reply], vec![], vec![]);
            let creates = Arc::new(AtomicUsize::new(0));
            let result = XpcProductionRouteBoundary::connect_with_factory(
                Box::new(MockFactory::new(
                    vec![Arc::clone(&initial), Arc::clone(&fresh)],
                    Arc::clone(&creates),
                )),
                test_policy(3),
            );
            assert!(result.is_ok());
            let Ok(mut boundary) = result else {
                return;
            };
            let profile = test_profile();
            assert!(profile.is_some());
            let Some(profile) = profile else {
                return;
            };

            assert_eq!(
                boundary.apply(
                    &profile,
                    operation,
                    &test_tunnel(operation),
                    42,
                    &MihomoTunSnapshot::inactive(),
                ),
                Err(NetworkErrorCode::SidecarUnavailable)
            );
            assert_eq!(boundary.reconciliation_error, Some(expected));
            assert!(boundary.active.is_some());
            assert!(boundary.active_owner.is_some());
            assert!(boundary.mutations_blocked);
            assert_eq!(fresh.counts.discover.load(Ordering::SeqCst), 1);
            assert_no_mutation_calls(&fresh);
            assert_eq!(creates.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn helper_status_requires_exact_state_and_no_embedded_error() {
        let status = RouteHelperStatus {
            protocol_version: ROUTE_HELPER_PROTOCOL_VERSION,
            state: RouteHelperState::Prepared,
            operation_id: Some("operation.test".into()),
            error_code: None,
        };
        assert_eq!(require_helper_status(&status, RouteHelperState::Prepared), Ok(()));
        assert_eq!(
            require_helper_status(&status, RouteHelperState::Applied),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        let failed = RouteHelperStatus {
            error_code: Some(NetworkErrorCode::PermissionDenied),
            ..status
        };
        assert_eq!(
            require_helper_status(&failed, RouteHelperState::Prepared),
            Err(NetworkErrorCode::PermissionDenied)
        );
    }
}
