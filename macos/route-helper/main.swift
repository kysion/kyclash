import Foundation
import Darwin
import OSLog

private let protocolVersion: UInt8 = 2
private let legacyProtocolVersion: UInt8 = 1
// v3 is the signed production listener surface. The legacy v2 coordinator is
// retained only behind an explicit lab flag and for compatibility tests.
private let routeHelperV3ProtocolVersion: UInt8 = 3
private let routeBrokerProtocolVersion: UInt8 = 1
private let maximumMihomoInterfaces = 1
private let maximumDarwinInterfaceBytes = 15
private let coordinatorSelfTestConnectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!
private let appRequirement = "anchor apple generic and identifier \"net.kysion.kyclash\" and certificate leaf[subject.OU] = \"RQUQ8Y3S9H\""
private let routeHelperLogger = Logger(
    subsystem: "net.kysion.kyclash.route-helper",
    category: "xpc"
)

// NSXPCConnection exposes these two values as security attributes derived
// from the peer's Mach audit token.  Keep only the PID and real audit-session
// identifier for the lifetime of one exported service object; the effective
// UID is checked at admission time but is deliberately not retained.
private struct ClientAuditIdentity: Equatable {
    let processID: pid_t
    let auditSessionID: au_asid_t

    static func validated(
        effectiveUserID: uid_t,
        processID: pid_t,
        auditSessionID: au_asid_t
    ) -> ClientAuditIdentity? {
        guard effectiveUserID != 0,
              processID > 1,
              auditSessionID > AU_DEFAUDITSID,
              auditSessionID != AU_ASSIGN_ASID
        else { return nil }
        return ClientAuditIdentity(
            processID: processID,
            auditSessionID: auditSessionID
        )
    }

    static func validated(connection: NSXPCConnection) -> ClientAuditIdentity? {
        // Foundation's public macOS 13+ accessors are the reliable equivalent
        // of applying audit_token_to_pid/audit_token_to_asid to the connection
        // audit token; unlike caller-supplied PID/session fields they are
        // populated by the XPC transport.
        validated(
            effectiveUserID: connection.effectiveUserIdentifier,
            processID: connection.processIdentifier,
            auditSessionID: connection.auditSessionIdentifier
        )
    }
}

@objc(KCRLeaseReference)
final class LeaseReference: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let version: UInt8
    let leaseID: String
    let operationID: String

    init(version: UInt8, leaseID: String, operationID: String) {
        self.version = version
        self.leaseID = leaseID
        self.operationID = operationID
    }

    required init?(coder: NSCoder) {
        let rawVersion = coder.decodeInteger(forKey: "version")
        guard (0...Int(UInt8.max)).contains(rawVersion) else { return nil }
        guard let lease = coder.decodeObject(of: NSString.self, forKey: "leaseID") as String?,
              let operation = coder.decodeObject(of: NSString.self, forKey: "operationID") as String?
        else { return nil }
        version = UInt8(rawVersion)
        leaseID = lease
        operationID = operation
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(version), forKey: "version")
        coder.encode(leaseID as NSString, forKey: "leaseID")
        coder.encode(operationID as NSString, forKey: "operationID")
    }

    func isValid() -> Bool {
        version == protocolVersion && validIdentifier(leaseID) && validIdentifier(operationID)
    }
}

@objc(KCRLeaseOwner)
final class LeaseOwner: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let reference: LeaseReference
    let sidecarInstanceID: String
    let interfaceName: String
    let tunnelOperationID: String
    let mtu: UInt16
    let profileRevision: UInt64
    let hasIPv4: Bool
    let hasIPv6: Bool
    let activeMihomoTunInterfaces: [String]
    let privateCIDRs: [String]

    init(reference: LeaseReference, sidecarInstanceID: String, interfaceName: String,
         tunnelOperationID: String, mtu: UInt16, profileRevision: UInt64,
         hasIPv4: Bool = true, hasIPv6: Bool = true,
         activeMihomoTunInterfaces: [String] = [], privateCIDRs: [String]) {
        self.reference = reference
        self.sidecarInstanceID = sidecarInstanceID
        self.interfaceName = interfaceName
        self.tunnelOperationID = tunnelOperationID
        self.mtu = mtu
        self.profileRevision = profileRevision
        self.hasIPv4 = hasIPv4
        self.hasIPv6 = hasIPv6
        self.activeMihomoTunInterfaces = activeMihomoTunInterfaces
        self.privateCIDRs = privateCIDRs
    }

    required init?(coder: NSCoder) {
        guard let reference = coder.decodeObject(of: LeaseReference.self, forKey: "reference"),
              let instance = coder.decodeObject(of: NSString.self, forKey: "sidecarInstanceID") as String?,
              let interfaceName = coder.decodeObject(of: NSString.self, forKey: "interfaceName") as String?,
              let tunnelOperation = coder.decodeObject(of: NSString.self, forKey: "tunnelOperationID") as String?,
              coder.containsValue(forKey: "hasIPv4"),
              coder.containsValue(forKey: "hasIPv6"),
              let mihomoInterfaces = coder.decodeObject(of: [NSArray.self, NSString.self], forKey: "activeMihomoTunInterfaces") as? [String],
              let cidrs = coder.decodeObject(of: [NSArray.self, NSString.self], forKey: "privateCIDRs") as? [String]
        else { return nil }
        self.reference = reference
        sidecarInstanceID = instance
        self.interfaceName = interfaceName
        tunnelOperationID = tunnelOperation
        let rawMtu = coder.decodeInteger(forKey: "mtu")
        let rawRevision = coder.decodeInt64(forKey: "profileRevision")
        let rawHasIPv4 = coder.decodeInteger(forKey: "hasIPv4")
        let rawHasIPv6 = coder.decodeInteger(forKey: "hasIPv6")
        guard (0...Int(UInt16.max)).contains(rawMtu),
              rawRevision > 0,
              rawHasIPv4 == 0 || rawHasIPv4 == 1,
              rawHasIPv6 == 0 || rawHasIPv6 == 1
        else { return nil }
        mtu = UInt16(rawMtu)
        profileRevision = UInt64(rawRevision)
        hasIPv4 = rawHasIPv4 == 1
        hasIPv6 = rawHasIPv6 == 1
        activeMihomoTunInterfaces = mihomoInterfaces
        privateCIDRs = cidrs
    }

    func encode(with coder: NSCoder) {
        coder.encode(reference, forKey: "reference")
        coder.encode(sidecarInstanceID as NSString, forKey: "sidecarInstanceID")
        coder.encode(interfaceName as NSString, forKey: "interfaceName")
        coder.encode(tunnelOperationID as NSString, forKey: "tunnelOperationID")
        coder.encode(Int(mtu), forKey: "mtu")
        coder.encode(Int64(profileRevision), forKey: "profileRevision")
        // Keep the wire primitive identical to the Objective-C bridge.  A
        // keyed-archive BOOL is not decoded by `decodeInteger(forKey:)` as 1;
        // writing bounded integers prevents a valid dual-stack owner from
        // becoming false at the cross-language NSSecureCoding boundary.
        coder.encode(hasIPv4 ? 1 : 0, forKey: "hasIPv4")
        coder.encode(hasIPv6 ? 1 : 0, forKey: "hasIPv6")
        coder.encode(activeMihomoTunInterfaces as NSArray, forKey: "activeMihomoTunInterfaces")
        coder.encode(privateCIDRs as NSArray, forKey: "privateCIDRs")
    }

    func isValid() -> Bool {
        return reference.isValid()
            && validIdentifier(sidecarInstanceID)
            && validUtunInterface(interfaceName)
            && tunnelOperationID == "\(reference.operationID).prepare"
            && mtu == 1420 && profileRevision > 0 && profileRevision <= UInt64(Int64.max)
            && activeMihomoTunInterfaces.count <= maximumMihomoInterfaces
            && Set(activeMihomoTunInterfaces).count == activeMihomoTunInterfaces.count
            && activeMihomoTunInterfaces.sorted() == activeMihomoTunInterfaces
            && activeMihomoTunInterfaces.allSatisfy(validUtunInterface)
            && !activeMihomoTunInterfaces.contains(interfaceName)
            && !privateCIDRs.isEmpty && privateCIDRs.count <= 64
            && Set(privateCIDRs).count == privateCIDRs.count
            && privateCIDRs.allSatisfy(validCIDR)
            && privateCIDRs.allSatisfy { cidr in
                guard let network = parseRouteNetwork(cidr) else { return false }
                return network.ipv4 ? hasIPv4 : hasIPv6
            }
            && privateCIDRsAreDisjoint(privateCIDRs)
    }
}

private func privateCIDRsAreDisjoint(_ cidrs: [String]) -> Bool {
    for (index, value) in cidrs.enumerated() {
        guard let current = parseRouteNetwork(value) else { return false }
        for otherValue in cidrs.dropFirst(index + 1) {
            guard let other = parseRouteNetwork(otherValue) else { return false }
            if networksOverlap(current, other) { return false }
        }
    }
    return true
}

@objc(KCRReply)
final class HelperReply: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let state: String
    let errorCode: String?

    init(protocolVersion version: UInt8 = 2, state: String, errorCode: String? = nil) {
        self.protocolVersion = version
        self.state = state
        self.errorCode = errorCode
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              let state = coder.decodeObject(of: NSString.self, forKey: "state") as String?
        else { return nil }
        let rawProtocolVersion = coder.decodeInteger(forKey: "protocolVersion")
        guard (0...Int(UInt8.max)).contains(rawProtocolVersion) else { return nil }
        protocolVersion = UInt8(rawProtocolVersion)
        self.state = state
        errorCode = coder.decodeObject(of: NSString.self, forKey: "errorCode") as String?
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(state as NSString, forKey: "state")
        if let errorCode { coder.encode(errorCode as NSString, forKey: "errorCode") }
    }
}

// MARK: - Route-helper v3 production wire contract

/// The v3 reference is the complete, non-derivable ownership tuple.  In
/// particular, the broker generation is deliberately distinct from any Rust
/// runtime generation and must be copied from the broker start receipt.
@objc(KCRLeaseReferenceV3)
final class LeaseReferenceV3: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let brokerProtocolVersion: UInt8
    let brokerGeneration: UInt64
    let sidecarInstanceID: String
    let leaseID: String
    let operationID: String

    init(
        protocolVersion: UInt8 = routeHelperV3ProtocolVersion,
        brokerProtocolVersion: UInt8 = routeBrokerProtocolVersion,
        brokerGeneration: UInt64,
        sidecarInstanceID: String,
        leaseID: String,
        operationID: String
    ) {
        self.protocolVersion = protocolVersion
        self.brokerProtocolVersion = brokerProtocolVersion
        self.brokerGeneration = brokerGeneration
        self.sidecarInstanceID = sidecarInstanceID
        self.leaseID = leaseID
        self.operationID = operationID
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              coder.containsValue(forKey: "brokerProtocolVersion"),
              coder.containsValue(forKey: "brokerGeneration"),
              let sidecar = coder.decodeObject(of: NSString.self, forKey: "sidecarInstanceID") as String?,
              let lease = coder.decodeObject(of: NSString.self, forKey: "leaseID") as String?,
              let operation = coder.decodeObject(of: NSString.self, forKey: "operationID") as String?
        else { return nil }
        let rawProtocol = coder.decodeInteger(forKey: "protocolVersion")
        let rawBrokerProtocol = coder.decodeInteger(forKey: "brokerProtocolVersion")
        let rawGeneration = coder.decodeInt64(forKey: "brokerGeneration")
        guard (0...Int(UInt8.max)).contains(rawProtocol),
              (0...Int(UInt8.max)).contains(rawBrokerProtocol),
              rawGeneration > 0
        else { return nil }
        protocolVersion = UInt8(rawProtocol)
        brokerProtocolVersion = UInt8(rawBrokerProtocol)
        brokerGeneration = UInt64(rawGeneration)
        sidecarInstanceID = sidecar
        leaseID = lease
        operationID = operation
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(Int(brokerProtocolVersion), forKey: "brokerProtocolVersion")
        coder.encode(Int64(brokerGeneration), forKey: "brokerGeneration")
        coder.encode(sidecarInstanceID as NSString, forKey: "sidecarInstanceID")
        coder.encode(leaseID as NSString, forKey: "leaseID")
        coder.encode(operationID as NSString, forKey: "operationID")
    }

    func isValid() -> Bool {
        protocolVersion == routeHelperV3ProtocolVersion
            && brokerProtocolVersion == routeBrokerProtocolVersion
            && brokerGeneration > 0
            && brokerGeneration <= UInt64(Int64.max)
            && validIdentifier(sidecarInstanceID)
            && validIdentifier(leaseID)
            && validIdentifier(operationID)
    }
}

private func referencesEqualV3(_ lhs: LeaseReferenceV3, _ rhs: LeaseReferenceV3) -> Bool {
    lhs.protocolVersion == rhs.protocolVersion
        && lhs.brokerProtocolVersion == rhs.brokerProtocolVersion
        && lhs.brokerGeneration == rhs.brokerGeneration
        && lhs.sidecarInstanceID == rhs.sidecarInstanceID
        && lhs.leaseID == rhs.leaseID
        && lhs.operationID == rhs.operationID
}

/// v3 keeps route facts explicit and binds the duplicated sidecar identity to
/// the broker reference.  No command/path/dictionary is accepted on this
/// wire; only normalized route facts cross the XPC boundary.
@objc(KCRLeaseOwnerV3)
final class LeaseOwnerV3: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let reference: LeaseReferenceV3
    let sidecarInstanceID: String
    let interfaceName: String
    let tunnelOperationID: String
    let mtu: UInt16
    let profileRevision: UInt64
    let hasIPv4: Bool
    let hasIPv6: Bool
    let activeMihomoTunInterfaces: [String]
    let privateCIDRs: [String]

    init(
        reference: LeaseReferenceV3,
        sidecarInstanceID: String,
        interfaceName: String,
        tunnelOperationID: String,
        mtu: UInt16,
        profileRevision: UInt64,
        hasIPv4: Bool = true,
        hasIPv6: Bool = true,
        activeMihomoTunInterfaces: [String] = [],
        privateCIDRs: [String]
    ) {
        self.reference = reference
        self.sidecarInstanceID = sidecarInstanceID
        self.interfaceName = interfaceName
        self.tunnelOperationID = tunnelOperationID
        self.mtu = mtu
        self.profileRevision = profileRevision
        self.hasIPv4 = hasIPv4
        self.hasIPv6 = hasIPv6
        self.activeMihomoTunInterfaces = activeMihomoTunInterfaces
        self.privateCIDRs = privateCIDRs
    }

    required init?(coder: NSCoder) {
        guard let reference = coder.decodeObject(of: LeaseReferenceV3.self, forKey: "reference"),
              let instance = coder.decodeObject(of: NSString.self, forKey: "sidecarInstanceID") as String?,
              let interfaceName = coder.decodeObject(of: NSString.self, forKey: "interfaceName") as String?,
              let tunnelOperation = coder.decodeObject(of: NSString.self, forKey: "tunnelOperationID") as String?,
              coder.containsValue(forKey: "mtu"),
              coder.containsValue(forKey: "profileRevision"),
              coder.containsValue(forKey: "hasIPv4"),
              coder.containsValue(forKey: "hasIPv6"),
              let mihomoInterfaces = coder.decodeObject(
                  of: [NSArray.self, NSString.self], forKey: "activeMihomoTunInterfaces"
              ) as? [String],
              let cidrs = coder.decodeObject(
                  of: [NSArray.self, NSString.self], forKey: "privateCIDRs"
              ) as? [String]
        else { return nil }
        let rawMTU = coder.decodeInteger(forKey: "mtu")
        let rawRevision = coder.decodeInt64(forKey: "profileRevision")
        let rawHasIPv4 = coder.decodeInteger(forKey: "hasIPv4")
        let rawHasIPv6 = coder.decodeInteger(forKey: "hasIPv6")
        guard (0...Int(UInt16.max)).contains(rawMTU),
              rawRevision > 0,
              rawHasIPv4 == 0 || rawHasIPv4 == 1,
              rawHasIPv6 == 0 || rawHasIPv6 == 1
        else { return nil }
        self.reference = reference
        sidecarInstanceID = instance
        self.interfaceName = interfaceName
        tunnelOperationID = tunnelOperation
        mtu = UInt16(rawMTU)
        profileRevision = UInt64(rawRevision)
        hasIPv4 = rawHasIPv4 == 1
        hasIPv6 = rawHasIPv6 == 1
        activeMihomoTunInterfaces = mihomoInterfaces
        privateCIDRs = cidrs
    }

    func encode(with coder: NSCoder) {
        coder.encode(reference, forKey: "reference")
        coder.encode(sidecarInstanceID as NSString, forKey: "sidecarInstanceID")
        coder.encode(interfaceName as NSString, forKey: "interfaceName")
        coder.encode(tunnelOperationID as NSString, forKey: "tunnelOperationID")
        coder.encode(Int(mtu), forKey: "mtu")
        coder.encode(Int64(profileRevision), forKey: "profileRevision")
        // Keep BOOLs as bounded integer primitives for ObjC/Swift keyed
        // archive compatibility (decodeInteger must return 0 or 1).
        coder.encode(hasIPv4 ? 1 : 0, forKey: "hasIPv4")
        coder.encode(hasIPv6 ? 1 : 0, forKey: "hasIPv6")
        coder.encode(activeMihomoTunInterfaces as NSArray, forKey: "activeMihomoTunInterfaces")
        coder.encode(privateCIDRs as NSArray, forKey: "privateCIDRs")
    }

    func isValid() -> Bool {
        reference.isValid()
            && sidecarInstanceID == reference.sidecarInstanceID
            && validUtunInterface(interfaceName)
            && tunnelOperationID == "\(reference.operationID).prepare"
            && mtu == 1420
            && profileRevision > 0
            && profileRevision <= UInt64(Int64.max)
            && activeMihomoTunInterfaces.count <= maximumMihomoInterfaces
            && Set(activeMihomoTunInterfaces).count == activeMihomoTunInterfaces.count
            && activeMihomoTunInterfaces.sorted() == activeMihomoTunInterfaces
            && activeMihomoTunInterfaces.allSatisfy(validUtunInterface)
            && !activeMihomoTunInterfaces.contains(interfaceName)
            && !privateCIDRs.isEmpty
            && privateCIDRs.count <= 64
            && Set(privateCIDRs).count == privateCIDRs.count
            && privateCIDRs.allSatisfy(validCIDR)
            && privateCIDRs.allSatisfy { cidr in
                guard let network = parseRouteNetwork(cidr) else { return false }
                return network.ipv4 ? hasIPv4 : hasIPv6
            }
            && privateCIDRsAreDisjoint(privateCIDRs)
    }
}

/// Every v3 mutation reply echoes the complete reference and macro transition
/// number.  A discovery reply may omit the reference and uses transition 0.
@objc(KCRReplyV3)
final class HelperReplyV3: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let state: String
    let errorCode: String?
    let reference: LeaseReferenceV3?
    let transition: UInt64

    private static let validStates: Set<String> = [
        "idle", "hold_pending", "held", "applied", "retirement_pending",
        "released", "recovery_only", "failed_closed"
    ]

    // Keep this vocabulary closed at the XPC boundary.  Broker transport and
    // implementation details are normalized by the coordinator below; they
    // must never become arbitrary error strings in a privileged reply.
    private static let validErrorCodes: Set<String> = [
        "not_ready", "invalid_owner", "permission_denied", "route_conflict",
        "journal_write_failed", "journal_corrupt", "route_apply_failed",
        "rollback_failed", "release_failed", "recovery_required",
        "ownership_mismatch", "broker_protocol_failure", "broker_status_failed"
    ]

    init(
        protocolVersion: UInt8 = routeHelperV3ProtocolVersion,
        state: String,
        errorCode: String? = nil,
        reference: LeaseReferenceV3? = nil,
        transition: UInt64 = 0
    ) {
        self.protocolVersion = protocolVersion
        self.state = state
        self.errorCode = errorCode
        self.reference = reference
        self.transition = transition
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              coder.containsValue(forKey: "transition"),
              let state = coder.decodeObject(of: NSString.self, forKey: "state") as String?
        else { return nil }
        let rawProtocol = coder.decodeInteger(forKey: "protocolVersion")
        let rawTransition = coder.decodeInt64(forKey: "transition")
        guard (0...Int(UInt8.max)).contains(rawProtocol), rawTransition >= 0 else { return nil }
        protocolVersion = UInt8(rawProtocol)
        self.state = state
        errorCode = coder.decodeObject(of: NSString.self, forKey: "errorCode") as String?
        reference = coder.decodeObject(of: LeaseReferenceV3.self, forKey: "reference")
        transition = UInt64(rawTransition)
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(state as NSString, forKey: "state")
        if let errorCode { coder.encode(errorCode as NSString, forKey: "errorCode") }
        if let reference { coder.encode(reference, forKey: "reference") }
        coder.encode(Int64(transition), forKey: "transition")
    }

    func isValid() -> Bool {
        guard protocolVersion == routeHelperV3ProtocolVersion,
              Self.validStates.contains(state),
              errorCode.map({ Self.validErrorCodes.contains($0) }) ?? true
        else { return false }
        if let reference {
            return reference.isValid() && transition > 0
        }
        return transition == 0
            && (state == "idle" || state == "recovery_only" || state == "failed_closed")
    }

    func matches(_ expected: LeaseReferenceV3, transition expectedTransition: UInt64? = nil) -> Bool {
        guard isValid(), let reference, referencesEqualV3(reference, expected) else { return false }
        return expectedTransition.map { transition == $0 } ?? true
    }
}

@objc(KCRRouteHelperV3Protocol)
protocol RouteHelperV3Protocol {
    func discoverV3(reply: @escaping (HelperReplyV3) -> Void)
    func beginV3(_ owner: LeaseOwnerV3, reply: @escaping (HelperReplyV3) -> Void)
    func applyV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void)
    func rollbackV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void)
    func recoverV3(_ owner: LeaseOwnerV3, reply: @escaping (HelperReplyV3) -> Void)
    func heartbeatV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void)
    func statusV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void)
}

/// Builds the production v3 interface. The signed helper installs this exact
/// interface on its fixed launchd Mach service; legacy v2 remains available
/// only to explicit source/self-test paths and can never authorize v3 routes.
private func routeHelperV3Interface() -> NSXPCInterface {
    let interface = NSXPCInterface(with: RouteHelperV3Protocol.self)
    let replyClasses = NSSet(objects: HelperReplyV3.self, LeaseReferenceV3.self, NSString.self) as! Set<AnyHashable>
    let ownerClasses = NSSet(
        objects: LeaseOwnerV3.self, LeaseReferenceV3.self, NSArray.self, NSString.self
    ) as! Set<AnyHashable>
    let referenceClasses = NSSet(objects: LeaseReferenceV3.self, NSString.self) as! Set<AnyHashable>

    interface.setClasses(replyClasses, for: #selector(RouteHelperV3Protocol.discoverV3(reply:)), argumentIndex: 0, ofReply: true)
    for selector in [
        #selector(RouteHelperV3Protocol.beginV3(_:reply:)),
        #selector(RouteHelperV3Protocol.recoverV3(_:reply:)),
    ] {
        interface.setClasses(ownerClasses, for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(replyClasses, for: selector, argumentIndex: 0, ofReply: true)
    }
    for selector in [
        #selector(RouteHelperV3Protocol.applyV3(_:reply:)),
        #selector(RouteHelperV3Protocol.rollbackV3(_:reply:)),
        #selector(RouteHelperV3Protocol.heartbeatV3(_:reply:)),
        #selector(RouteHelperV3Protocol.statusV3(_:reply:)),
    ] {
        interface.setClasses(referenceClasses, for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(replyClasses, for: selector, argumentIndex: 0, ofReply: true)
    }
    return interface
}

@objc(KCRRouteHelperProtocol)
protocol RouteHelperProtocol {
    func discover(reply: @escaping (HelperReply) -> Void)
    func begin(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void)
    func apply(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void)
    func rollback(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void)
    func recover(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void)
    func heartbeat(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void)
    func status(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void)
}

private func routeHelperInterface() -> NSXPCInterface {
    let interface = NSXPCInterface(with: RouteHelperProtocol.self)
    let replyClasses = NSSet(objects: HelperReply.self) as! Set<AnyHashable>
    let ownerClasses = NSSet(objects: LeaseOwner.self, LeaseReference.self, NSArray.self, NSString.self) as! Set<AnyHashable>
    let referenceClasses = NSSet(objects: LeaseReference.self, NSString.self) as! Set<AnyHashable>

    interface.setClasses(replyClasses, for: #selector(RouteHelperProtocol.discover(reply:)), argumentIndex: 0, ofReply: true)
    interface.setClasses(ownerClasses, for: #selector(RouteHelperProtocol.begin(_:reply:)), argumentIndex: 0, ofReply: false)
    interface.setClasses(replyClasses, for: #selector(RouteHelperProtocol.begin(_:reply:)), argumentIndex: 0, ofReply: true)
    interface.setClasses(referenceClasses, for: #selector(RouteHelperProtocol.apply(_:reply:)), argumentIndex: 0, ofReply: false)
    interface.setClasses(replyClasses, for: #selector(RouteHelperProtocol.apply(_:reply:)), argumentIndex: 0, ofReply: true)
    interface.setClasses(referenceClasses, for: #selector(RouteHelperProtocol.rollback(_:reply:)), argumentIndex: 0, ofReply: false)
    interface.setClasses(replyClasses, for: #selector(RouteHelperProtocol.rollback(_:reply:)), argumentIndex: 0, ofReply: true)
    interface.setClasses(ownerClasses, for: #selector(RouteHelperProtocol.recover(_:reply:)), argumentIndex: 0, ofReply: false)
    interface.setClasses(replyClasses, for: #selector(RouteHelperProtocol.recover(_:reply:)), argumentIndex: 0, ofReply: true)
    interface.setClasses(referenceClasses, for: #selector(RouteHelperProtocol.heartbeat(_:reply:)), argumentIndex: 0, ofReply: false)
    interface.setClasses(replyClasses, for: #selector(RouteHelperProtocol.heartbeat(_:reply:)), argumentIndex: 0, ofReply: true)
    interface.setClasses(referenceClasses, for: #selector(RouteHelperProtocol.status(_:reply:)), argumentIndex: 0, ofReply: false)
    interface.setClasses(replyClasses, for: #selector(RouteHelperProtocol.status(_:reply:)), argumentIndex: 0, ofReply: true)
    return interface
}

private struct StrictCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int? = nil

    init(_ stringValue: String) { self.stringValue = stringValue }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private func rejectUnknownJournalKeys(
    _ container: KeyedDecodingContainer<StrictCodingKey>,
    allowed: Set<String>,
    optional: Set<String> = [],
    decoder: Decoder
) throws {
    let keys = Set(container.allKeys.map(\.stringValue))
    let required = allowed.subtracting(optional)
    guard keys.isSuperset(of: required), keys.isSubset(of: allowed) else {
        throw DecodingError.dataCorruptedError(
            forKey: container.allKeys.first ?? StrictCodingKey("journal"),
            in: container,
            debugDescription: "journal contains an unknown or missing field"
        )
    }
    _ = decoder
}

private struct JournalOwner: Codable, Equatable {
    let protocolVersion: UInt8
    let leaseID: String
    let operationID: String
    let sidecarInstanceID: String
    let interfaceName: String
    let tunnelOperationID: String
    let mtu: UInt16
    let profileRevision: UInt64
    let hasIPv4: Bool
    let hasIPv6: Bool
    let activeMihomoTunInterfaces: [String]
    let privateCIDRs: [String]

    init(_ owner: LeaseOwner) {
        protocolVersion = owner.reference.version
        leaseID = owner.reference.leaseID
        operationID = owner.reference.operationID
        sidecarInstanceID = owner.sidecarInstanceID
        interfaceName = owner.interfaceName
        tunnelOperationID = owner.tunnelOperationID
        mtu = owner.mtu
        profileRevision = owner.profileRevision
        hasIPv4 = owner.hasIPv4
        hasIPv6 = owner.hasIPv6
        activeMihomoTunInterfaces = owner.activeMihomoTunInterfaces
        privateCIDRs = owner.privateCIDRs
    }

    private static let allowedKeys: Set<String> = [
        "protocolVersion", "leaseID", "operationID", "sidecarInstanceID", "interfaceName",
        "tunnelOperationID", "mtu", "profileRevision", "hasIPv4", "hasIPv6",
        "activeMihomoTunInterfaces", "privateCIDRs"
    ]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: StrictCodingKey.self)
        try rejectUnknownJournalKeys(container, allowed: Self.allowedKeys, decoder: decoder)
        protocolVersion = try container.decode(UInt8.self, forKey: StrictCodingKey("protocolVersion"))
        leaseID = try container.decode(String.self, forKey: StrictCodingKey("leaseID"))
        operationID = try container.decode(String.self, forKey: StrictCodingKey("operationID"))
        sidecarInstanceID = try container.decode(String.self, forKey: StrictCodingKey("sidecarInstanceID"))
        interfaceName = try container.decode(String.self, forKey: StrictCodingKey("interfaceName"))
        tunnelOperationID = try container.decode(String.self, forKey: StrictCodingKey("tunnelOperationID"))
        mtu = try container.decode(UInt16.self, forKey: StrictCodingKey("mtu"))
        profileRevision = try container.decode(UInt64.self, forKey: StrictCodingKey("profileRevision"))
        hasIPv4 = try container.decode(Bool.self, forKey: StrictCodingKey("hasIPv4"))
        hasIPv6 = try container.decode(Bool.self, forKey: StrictCodingKey("hasIPv6"))
        activeMihomoTunInterfaces = try container.decode([String].self, forKey: StrictCodingKey("activeMihomoTunInterfaces"))
        privateCIDRs = try container.decode([String].self, forKey: StrictCodingKey("privateCIDRs"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: StrictCodingKey.self)
        try container.encode(protocolVersion, forKey: StrictCodingKey("protocolVersion"))
        try container.encode(leaseID, forKey: StrictCodingKey("leaseID"))
        try container.encode(operationID, forKey: StrictCodingKey("operationID"))
        try container.encode(sidecarInstanceID, forKey: StrictCodingKey("sidecarInstanceID"))
        try container.encode(interfaceName, forKey: StrictCodingKey("interfaceName"))
        try container.encode(tunnelOperationID, forKey: StrictCodingKey("tunnelOperationID"))
        try container.encode(mtu, forKey: StrictCodingKey("mtu"))
        try container.encode(profileRevision, forKey: StrictCodingKey("profileRevision"))
        try container.encode(hasIPv4, forKey: StrictCodingKey("hasIPv4"))
        try container.encode(hasIPv6, forKey: StrictCodingKey("hasIPv6"))
        try container.encode(activeMihomoTunInterfaces, forKey: StrictCodingKey("activeMihomoTunInterfaces"))
        try container.encode(privateCIDRs, forKey: StrictCodingKey("privateCIDRs"))
    }

    func isValid() -> Bool {
        protocolVersion == protocolVersionValue && LeaseOwner(
            reference: LeaseReference(
                version: protocolVersion,
                leaseID: leaseID,
                operationID: operationID
            ),
            sidecarInstanceID: sidecarInstanceID,
            interfaceName: interfaceName,
            tunnelOperationID: tunnelOperationID,
            mtu: mtu,
            profileRevision: profileRevision,
            hasIPv4: hasIPv4,
            hasIPv6: hasIPv6,
            activeMihomoTunInterfaces: activeMihomoTunInterfaces,
            privateCIDRs: privateCIDRs
        ).isValid()
    }

    // Keep the comparison above independent from the stored-property name.
    // Swift resolves an unqualified `protocolVersion` in this method to the
    // property, so use a separately named constant for the active wire
    // version.
}

private let protocolVersionValue = protocolVersion

// Journals written by the pre-v2 helper intentionally have a separate model.
// They are accepted only during startup reconciliation and are never promoted
// to an active v2 transaction.  Keeping a strict decoder here prevents a
// malformed/forged v2 document from being silently interpreted as legacy.
private struct LegacyJournalOwner: Codable, Equatable {
    let leaseID: String
    let operationID: String
    let sidecarInstanceID: String
    let interfaceName: String
    let tunnelOperationID: String
    let mtu: UInt16
    let profileRevision: UInt64
    let privateCIDRs: [String]

    private static let allowedKeys: Set<String> = [
        "leaseID", "operationID", "sidecarInstanceID", "interfaceName",
        "tunnelOperationID", "mtu", "profileRevision", "privateCIDRs"
    ]

    init(_ owner: JournalOwner) {
        leaseID = owner.leaseID
        operationID = owner.operationID
        sidecarInstanceID = owner.sidecarInstanceID
        interfaceName = owner.interfaceName
        tunnelOperationID = owner.tunnelOperationID
        mtu = owner.mtu
        profileRevision = owner.profileRevision
        privateCIDRs = owner.privateCIDRs
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: StrictCodingKey.self)
        try rejectUnknownJournalKeys(container, allowed: Self.allowedKeys, decoder: decoder)
        leaseID = try container.decode(String.self, forKey: StrictCodingKey("leaseID"))
        operationID = try container.decode(String.self, forKey: StrictCodingKey("operationID"))
        sidecarInstanceID = try container.decode(String.self, forKey: StrictCodingKey("sidecarInstanceID"))
        interfaceName = try container.decode(String.self, forKey: StrictCodingKey("interfaceName"))
        tunnelOperationID = try container.decode(String.self, forKey: StrictCodingKey("tunnelOperationID"))
        mtu = try container.decode(UInt16.self, forKey: StrictCodingKey("mtu"))
        profileRevision = try container.decode(UInt64.self, forKey: StrictCodingKey("profileRevision"))
        privateCIDRs = try container.decode([String].self, forKey: StrictCodingKey("privateCIDRs"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: StrictCodingKey.self)
        try container.encode(leaseID, forKey: StrictCodingKey("leaseID"))
        try container.encode(operationID, forKey: StrictCodingKey("operationID"))
        try container.encode(sidecarInstanceID, forKey: StrictCodingKey("sidecarInstanceID"))
        try container.encode(interfaceName, forKey: StrictCodingKey("interfaceName"))
        try container.encode(tunnelOperationID, forKey: StrictCodingKey("tunnelOperationID"))
        try container.encode(mtu, forKey: StrictCodingKey("mtu"))
        try container.encode(profileRevision, forKey: StrictCodingKey("profileRevision"))
        try container.encode(privateCIDRs, forKey: StrictCodingKey("privateCIDRs"))
    }

    func isValid() -> Bool {
        validIdentifier(leaseID)
            && validIdentifier(operationID)
            && validIdentifier(sidecarInstanceID)
            && validUtunInterface(interfaceName)
            && tunnelOperationID == "\(operationID).prepare"
            && mtu == 1420
            && profileRevision > 0
            && profileRevision <= UInt64(Int64.max)
            && !privateCIDRs.isEmpty
            && privateCIDRs.count <= 64
            && Set(privateCIDRs).count == privateCIDRs.count
            && privateCIDRs.allSatisfy(validCIDR)
            && privateCIDRsAreDisjoint(privateCIDRs)
    }
}

private struct LegacyRouteJournal: Codable {
    let version: UInt8
    var owner: LegacyJournalOwner
    var pendingCIDR: String?
    var appliedCIDRs: [String]

    private static let allowedKeys: Set<String> = ["version", "owner", "pendingCIDR", "appliedCIDRs"]

    init(version: UInt8, owner: LegacyJournalOwner, pendingCIDR: String?, appliedCIDRs: [String]) {
        self.version = version
        self.owner = owner
        self.pendingCIDR = pendingCIDR
        self.appliedCIDRs = appliedCIDRs
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: StrictCodingKey.self)
        try rejectUnknownJournalKeys(
            container,
            allowed: Self.allowedKeys,
            optional: ["pendingCIDR"],
            decoder: decoder
        )
        version = try container.decode(UInt8.self, forKey: StrictCodingKey("version"))
        owner = try container.decode(LegacyJournalOwner.self, forKey: StrictCodingKey("owner"))
        pendingCIDR = try container.decodeIfPresent(String.self, forKey: StrictCodingKey("pendingCIDR"))
        appliedCIDRs = try container.decode([String].self, forKey: StrictCodingKey("appliedCIDRs"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: StrictCodingKey.self)
        try container.encode(version, forKey: StrictCodingKey("version"))
        try container.encode(owner, forKey: StrictCodingKey("owner"))
        try container.encodeIfPresent(pendingCIDR, forKey: StrictCodingKey("pendingCIDR"))
        try container.encode(appliedCIDRs, forKey: StrictCodingKey("appliedCIDRs"))
    }

    func isValid() -> Bool {
        guard version == legacyProtocolVersion,
              owner.isValid(),
              Set(appliedCIDRs).count == appliedCIDRs.count,
              appliedCIDRs.count <= owner.privateCIDRs.count,
              appliedCIDRs.allSatisfy(validCIDR),
              appliedCIDRs.allSatisfy({ owner.privateCIDRs.contains($0) }),
              pendingCIDR.map({ validCIDR($0) && owner.privateCIDRs.contains($0) }) ?? true
        else { return false }
        // Unlike the v2 journal, a v1 crash could leave pendingCIDR and the
        // applied list overlapping.  That state is safe for rollback-only
        // recovery, so do not reject it here; the migration deduplicates the
        // deletion set and never writes a new v2 journal.
        return true
    }
}

private struct RouteJournal: Codable {
    let version: UInt8
    var owner: JournalOwner
    var pendingCIDR: String?
    var appliedCIDRs: [String]

    init(version: UInt8, owner: JournalOwner, pendingCIDR: String?, appliedCIDRs: [String]) {
        self.version = version
        self.owner = owner
        self.pendingCIDR = pendingCIDR
        self.appliedCIDRs = appliedCIDRs
    }

    private static let allowedKeys: Set<String> = ["version", "owner", "pendingCIDR", "appliedCIDRs"]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: StrictCodingKey.self)
        try rejectUnknownJournalKeys(
            container,
            allowed: Self.allowedKeys,
            optional: ["pendingCIDR"],
            decoder: decoder
        )
        version = try container.decode(UInt8.self, forKey: StrictCodingKey("version"))
        owner = try container.decode(JournalOwner.self, forKey: StrictCodingKey("owner"))
        pendingCIDR = try container.decodeIfPresent(String.self, forKey: StrictCodingKey("pendingCIDR"))
        appliedCIDRs = try container.decode([String].self, forKey: StrictCodingKey("appliedCIDRs"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: StrictCodingKey.self)
        try container.encode(version, forKey: StrictCodingKey("version"))
        try container.encode(owner, forKey: StrictCodingKey("owner"))
        try container.encodeIfPresent(pendingCIDR, forKey: StrictCodingKey("pendingCIDR"))
        try container.encode(appliedCIDRs, forKey: StrictCodingKey("appliedCIDRs"))
    }

    func isValid() -> Bool {
        guard version == protocolVersion,
              owner.isValid(),
              Set(appliedCIDRs).count == appliedCIDRs.count,
              appliedCIDRs.count <= owner.privateCIDRs.count,
              appliedCIDRs.allSatisfy(validCIDR),
              appliedCIDRs.allSatisfy({ owner.privateCIDRs.contains($0) }),
              pendingCIDR.map({ validCIDR($0) && owner.privateCIDRs.contains($0) }) ?? true,
              pendingCIDR.map({ !appliedCIDRs.contains($0) }) ?? true
        else { return false }
        return true
    }
}

// v3 journal records are deliberately a separate Codable schema.  A v2/v1
// record can therefore be classified for rollback-only recovery without ever
// being coerced into a broker-held v3 lease.
private enum RouteJournalStateV3: String, Codable {
    case holdPending = "hold_pending"
    case held
    case applied
    case retirementPending = "retirement_pending"
    case released

    var permitsFirstRouteMutation: Bool { self == .held }
}

private struct JournalOwnerV3: Codable, Equatable {
    let protocolVersion: UInt8
    let brokerProtocolVersion: UInt8
    let brokerGeneration: UInt64
    let sidecarInstanceID: String
    let leaseID: String
    let operationID: String
    let interfaceName: String
    let tunnelOperationID: String
    let mtu: UInt16
    let profileRevision: UInt64
    let hasIPv4: Bool
    let hasIPv6: Bool
    let activeMihomoTunInterfaces: [String]
    let privateCIDRs: [String]

    init(_ owner: LeaseOwnerV3) {
        protocolVersion = owner.reference.protocolVersion
        brokerProtocolVersion = owner.reference.brokerProtocolVersion
        brokerGeneration = owner.reference.brokerGeneration
        sidecarInstanceID = owner.sidecarInstanceID
        leaseID = owner.reference.leaseID
        operationID = owner.reference.operationID
        interfaceName = owner.interfaceName
        tunnelOperationID = owner.tunnelOperationID
        mtu = owner.mtu
        profileRevision = owner.profileRevision
        hasIPv4 = owner.hasIPv4
        hasIPv6 = owner.hasIPv6
        activeMihomoTunInterfaces = owner.activeMihomoTunInterfaces
        privateCIDRs = owner.privateCIDRs
    }

    private static let allowedKeys: Set<String> = [
        "protocolVersion", "brokerProtocolVersion", "brokerGeneration",
        "sidecarInstanceID", "leaseID", "operationID", "interfaceName",
        "tunnelOperationID", "mtu", "profileRevision", "hasIPv4", "hasIPv6",
        "activeMihomoTunInterfaces", "privateCIDRs"
    ]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: StrictCodingKey.self)
        try rejectUnknownJournalKeys(container, allowed: Self.allowedKeys, decoder: decoder)
        protocolVersion = try container.decode(UInt8.self, forKey: StrictCodingKey("protocolVersion"))
        brokerProtocolVersion = try container.decode(UInt8.self, forKey: StrictCodingKey("brokerProtocolVersion"))
        brokerGeneration = try container.decode(UInt64.self, forKey: StrictCodingKey("brokerGeneration"))
        sidecarInstanceID = try container.decode(String.self, forKey: StrictCodingKey("sidecarInstanceID"))
        leaseID = try container.decode(String.self, forKey: StrictCodingKey("leaseID"))
        operationID = try container.decode(String.self, forKey: StrictCodingKey("operationID"))
        interfaceName = try container.decode(String.self, forKey: StrictCodingKey("interfaceName"))
        tunnelOperationID = try container.decode(String.self, forKey: StrictCodingKey("tunnelOperationID"))
        mtu = try container.decode(UInt16.self, forKey: StrictCodingKey("mtu"))
        profileRevision = try container.decode(UInt64.self, forKey: StrictCodingKey("profileRevision"))
        hasIPv4 = try container.decode(Bool.self, forKey: StrictCodingKey("hasIPv4"))
        hasIPv6 = try container.decode(Bool.self, forKey: StrictCodingKey("hasIPv6"))
        activeMihomoTunInterfaces = try container.decode(
            [String].self, forKey: StrictCodingKey("activeMihomoTunInterfaces")
        )
        privateCIDRs = try container.decode([String].self, forKey: StrictCodingKey("privateCIDRs"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: StrictCodingKey.self)
        try container.encode(protocolVersion, forKey: StrictCodingKey("protocolVersion"))
        try container.encode(brokerProtocolVersion, forKey: StrictCodingKey("brokerProtocolVersion"))
        try container.encode(brokerGeneration, forKey: StrictCodingKey("brokerGeneration"))
        try container.encode(sidecarInstanceID, forKey: StrictCodingKey("sidecarInstanceID"))
        try container.encode(leaseID, forKey: StrictCodingKey("leaseID"))
        try container.encode(operationID, forKey: StrictCodingKey("operationID"))
        try container.encode(interfaceName, forKey: StrictCodingKey("interfaceName"))
        try container.encode(tunnelOperationID, forKey: StrictCodingKey("tunnelOperationID"))
        try container.encode(mtu, forKey: StrictCodingKey("mtu"))
        try container.encode(profileRevision, forKey: StrictCodingKey("profileRevision"))
        try container.encode(hasIPv4, forKey: StrictCodingKey("hasIPv4"))
        try container.encode(hasIPv6, forKey: StrictCodingKey("hasIPv6"))
        try container.encode(activeMihomoTunInterfaces, forKey: StrictCodingKey("activeMihomoTunInterfaces"))
        try container.encode(privateCIDRs, forKey: StrictCodingKey("privateCIDRs"))
    }

    func asOwner() -> LeaseOwnerV3 {
        LeaseOwnerV3(
            reference: LeaseReferenceV3(
                protocolVersion: protocolVersion,
                brokerProtocolVersion: brokerProtocolVersion,
                brokerGeneration: brokerGeneration,
                sidecarInstanceID: sidecarInstanceID,
                leaseID: leaseID,
                operationID: operationID
            ),
            sidecarInstanceID: sidecarInstanceID,
            interfaceName: interfaceName,
            tunnelOperationID: tunnelOperationID,
            mtu: mtu,
            profileRevision: profileRevision,
            hasIPv4: hasIPv4,
            hasIPv6: hasIPv6,
            activeMihomoTunInterfaces: activeMihomoTunInterfaces,
            privateCIDRs: privateCIDRs
        )
    }

    func isValid() -> Bool {
        asOwner().isValid()
    }
}

private struct RouteJournalV3: Codable, Equatable {
    let version: UInt8
    var state: RouteJournalStateV3
    var transition: UInt64
    var owner: JournalOwnerV3
    var pendingCIDR: String?
    var appliedCIDRs: [String]

    init(
        version: UInt8 = routeHelperV3ProtocolVersion,
        state: RouteJournalStateV3,
        transition: UInt64,
        owner: JournalOwnerV3,
        pendingCIDR: String?,
        appliedCIDRs: [String]
    ) {
        self.version = version
        self.state = state
        self.transition = transition
        self.owner = owner
        self.pendingCIDR = pendingCIDR
        self.appliedCIDRs = appliedCIDRs
    }

    private static let allowedKeys: Set<String> = [
        "version", "state", "transition", "owner", "pendingCIDR", "appliedCIDRs"
    ]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: StrictCodingKey.self)
        try rejectUnknownJournalKeys(
            container,
            allowed: Self.allowedKeys,
            optional: ["pendingCIDR"],
            decoder: decoder
        )
        version = try container.decode(UInt8.self, forKey: StrictCodingKey("version"))
        state = try container.decode(RouteJournalStateV3.self, forKey: StrictCodingKey("state"))
        transition = try container.decode(UInt64.self, forKey: StrictCodingKey("transition"))
        owner = try container.decode(JournalOwnerV3.self, forKey: StrictCodingKey("owner"))
        pendingCIDR = try container.decodeIfPresent(String.self, forKey: StrictCodingKey("pendingCIDR"))
        appliedCIDRs = try container.decode([String].self, forKey: StrictCodingKey("appliedCIDRs"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: StrictCodingKey.self)
        try container.encode(version, forKey: StrictCodingKey("version"))
        try container.encode(state, forKey: StrictCodingKey("state"))
        try container.encode(transition, forKey: StrictCodingKey("transition"))
        try container.encode(owner, forKey: StrictCodingKey("owner"))
        try container.encodeIfPresent(pendingCIDR, forKey: StrictCodingKey("pendingCIDR"))
        try container.encode(appliedCIDRs, forKey: StrictCodingKey("appliedCIDRs"))
    }

    static func holdPending(owner: LeaseOwnerV3) -> RouteJournalV3 {
        RouteJournalV3(
            state: .holdPending,
            transition: 1,
            owner: JournalOwnerV3(owner),
            pendingCIDR: nil,
            appliedCIDRs: []
        )
    }

    func isValid() -> Bool {
        guard version == routeHelperV3ProtocolVersion,
              transition > 0,
              owner.isValid(),
              Set(appliedCIDRs).count == appliedCIDRs.count,
              appliedCIDRs.count <= owner.privateCIDRs.count,
              appliedCIDRs.allSatisfy(validCIDR),
              appliedCIDRs.allSatisfy({ owner.privateCIDRs.contains($0) }),
              pendingCIDR.map({ validCIDR($0) && owner.privateCIDRs.contains($0) }) ?? true,
              pendingCIDR.map({
                  // Held/Applied records may mark an already-owned route
                  // before deletion; the coordinator proves absence after
                  // the mutation. Add-intent records remain disjoint.
                  self.state == .held || self.state == .applied || !self.appliedCIDRs.contains($0)
              }) ?? true
        else { return false }

        switch state {
        case .holdPending:
            return transition == 1 && pendingCIDR == nil && appliedCIDRs.isEmpty
        case .held:
            // A partial add or a cleanup retry can retain a CIDR marker while
            // the broker hold is still authoritative. Only this state permits
            // a first route mutation.
            return transition == 2
        case .applied:
            // During rollback, Applied may retain a shrinking exact-owned set;
            // it is never treated as permission to add a new route.
            return transition == 3
        case .retirementPending:
            return (2...4).contains(transition)
                && pendingCIDR == nil
                && appliedCIDRs.isEmpty
        case .released:
            return (3...5).contains(transition)
                && pendingCIDR == nil
                && appliedCIDRs.isEmpty
        }
    }

    func reference() -> LeaseReferenceV3 {
        LeaseReferenceV3(
            protocolVersion: owner.protocolVersion,
            brokerProtocolVersion: owner.brokerProtocolVersion,
            brokerGeneration: owner.brokerGeneration,
            sidecarInstanceID: owner.sidecarInstanceID,
            leaseID: owner.leaseID,
            operationID: owner.operationID
        )
    }

    func requireReference(_ reference: LeaseReferenceV3) throws {
        guard isValid(), reference.isValid(), referencesEqualV3(reference, self.reference())
        else { throw RouteJournalTransitionError.ownershipMismatch }
    }

    func transitioned(
        to next: RouteJournalStateV3,
        reference: LeaseReferenceV3
    ) throws -> RouteJournalV3 {
        try requireReference(reference)
        let nextTransition = transition.addingReportingOverflow(1)
        guard !nextTransition.overflow,
              isValidTransitionV3(state, next),
              state != .released
        else { throw RouteJournalTransitionError.invalidStateTransition }

        var result = self
        result.state = next
        result.transition = nextTransition.partialValue
        if next == .retirementPending || next == .released {
            result.pendingCIDR = nil
            result.appliedCIDRs = []
        }
        guard result.isValid() else { throw RouteJournalTransitionError.invalidStateTransition }
        return result
    }

    func applying(_ event: RouteJournalTransitionV3) throws -> RouteJournalV3 {
        try requireReference(event.reference)
        let expectedTransition = transition.addingReportingOverflow(1)
        guard !expectedTransition.overflow,
              event.protocolVersion == routeHelperV3ProtocolVersion,
              event.fromState == state,
              event.transition == expectedTransition.partialValue,
              isValidTransitionV3(state, event.toState)
        else { throw RouteJournalTransitionError.replayDetected }
        return try transitioned(to: event.toState, reference: event.reference)
    }
}

private struct RouteJournalTransitionV3 {
    let protocolVersion: UInt8
    let fromState: RouteJournalStateV3
    let toState: RouteJournalStateV3
    let transition: UInt64
    let reference: LeaseReferenceV3
}

private enum RouteJournalTransitionError: Error, Equatable {
    case ownershipMismatch
    case invalidStateTransition
    case replayDetected
}

private func isValidTransitionV3(
    _ current: RouteJournalStateV3,
    _ next: RouteJournalStateV3
) -> Bool {
    switch (current, next) {
    case (.holdPending, .held),
         (.holdPending, .retirementPending),
         (.held, .applied),
         (.held, .retirementPending),
         (.applied, .retirementPending),
         (.retirementPending, .released):
        return true
    default:
        return false
    }
}

private enum RouteJournalEnvelope {
    case currentV3(RouteJournalV3)
    case recoveryOnlyV2(RouteJournal)
    case recoveryOnlyV1(LegacyRouteJournal)
}

private enum RouteJournalDecodeError: Error, Equatable {
    case corrupt
}

private struct RouteJournalVersionProbe: Decodable {
    let version: UInt8
}

/// Select exactly one schema from the top-level version.  This is deliberately
/// separate from `RouteCoordinator` until the v3 broker interlock is enabled;
/// the first slice proves that v2/v1 cannot be silently upgraded or cross-decoded.
private func decodeRouteJournalEnvelope(_ data: Data) throws -> RouteJournalEnvelope {
    let decoder = PropertyListDecoder()
    let version: UInt8
    do {
        version = try decoder.decode(RouteJournalVersionProbe.self, from: data).version
    } catch {
        throw RouteJournalDecodeError.corrupt
    }
    do {
        switch version {
        case routeHelperV3ProtocolVersion:
            let journal = try decoder.decode(RouteJournalV3.self, from: data)
            guard journal.isValid() else { throw RouteJournalDecodeError.corrupt }
            return .currentV3(journal)
        case protocolVersion:
            let journal = try decoder.decode(RouteJournal.self, from: data)
            guard journal.isValid() else { throw RouteJournalDecodeError.corrupt }
            return .recoveryOnlyV2(journal)
        case legacyProtocolVersion:
            let journal = try decoder.decode(LegacyRouteJournal.self, from: data)
            guard journal.isValid() else { throw RouteJournalDecodeError.corrupt }
            return .recoveryOnlyV1(journal)
        default:
            throw RouteJournalDecodeError.corrupt
        }
    } catch let error as RouteJournalDecodeError {
        throw error
    } catch {
        throw RouteJournalDecodeError.corrupt
    }
}

private struct RouteInspection {
    let ownedExact: Bool
    let foreignConflict: Bool

    var isAvailable: Bool { !ownedExact && !foreignConflict }
}

private protocol RouteExecuting {
    func inspect(
        cidrs: [String],
        interfaceName: String,
        trustedMihomoInterfaces: [String]
    ) -> [String: RouteInspection]?
    func mutate(action: String, cidr: String, interfaceName: String) -> Bool
}

private final class BoundedCommandOutput {
    private let lock = NSLock()
    private let limit: Int
    private var data = Data()
    private(set) var exceeded = false
    private(set) var reachedEOF = false

    init(limit: Int) { self.limit = limit }

    func append(_ chunk: Data) {
        lock.withLock {
            guard !exceeded else { return }
            if data.count + chunk.count > limit {
                exceeded = true
            } else {
                data.append(chunk)
            }
        }
    }

    func markEOF() { lock.withLock { reachedEOF = true } }

    func snapshot() -> (data: Data, exceeded: Bool, reachedEOF: Bool) {
        lock.withLock { (data, exceeded, reachedEOF) }
    }
}

private struct BoundedCommandResult {
    let terminationStatus: Int32
    let output: Data
}

private func runBoundedCommand(
    executable: String,
    arguments: [String],
    captureOutput: Bool,
    timeout: TimeInterval = 2,
    maxOutputBytes: Int = 1_048_576
) -> BoundedCommandResult? {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: executable)
    task.arguments = arguments
    task.standardInput = FileHandle.nullDevice
    task.standardError = FileHandle.nullDevice

    let pipe = captureOutput ? Pipe() : nil
    if let pipe { task.standardOutput = pipe } else { task.standardOutput = FileHandle.nullDevice }
    let state = captureOutput ? BoundedCommandOutput(limit: maxOutputBytes) : nil
    if let pipe, let state {
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                state.markEOF()
                handle.readabilityHandler = nil
            } else {
                state.append(chunk)
                if state.snapshot().exceeded { task.terminate() }
            }
        }
    }

    do {
        try task.run()
    } catch {
        pipe?.fileHandleForReading.readabilityHandler = nil
        return nil
    }

    let deadline = Date().addingTimeInterval(timeout)
    while task.isRunning,
          Date() < deadline,
          state?.snapshot().exceeded != true {
        Thread.sleep(forTimeInterval: 0.01)
    }

    var forcedTermination = false
    if task.isRunning {
        forcedTermination = true
        task.terminate()
        let terminateDeadline = Date().addingTimeInterval(0.25)
        while task.isRunning, Date() < terminateDeadline { Thread.sleep(forTimeInterval: 0.01) }
        if task.isRunning {
            kill(task.processIdentifier, SIGKILL)
            let killDeadline = Date().addingTimeInterval(0.25)
            while task.isRunning, Date() < killDeadline { Thread.sleep(forTimeInterval: 0.01) }
        }
    }
    guard !task.isRunning else {
        pipe?.fileHandleForReading.readabilityHandler = nil
        return nil
    }
    task.waitUntilExit()
    if let pipe, let state {
        // The readability handler drains the pipe while the process runs. Give
        // it a bounded window to observe EOF before detaching it.
        let eofDeadline = Date().addingTimeInterval(0.25)
        while !state.snapshot().reachedEOF, Date() < eofDeadline { Thread.sleep(forTimeInterval: 0.01) }
        pipe.fileHandleForReading.readabilityHandler = nil
        let snapshot = state.snapshot()
        guard !forcedTermination, !snapshot.exceeded, snapshot.reachedEOF else { return nil }
        return BoundedCommandResult(terminationStatus: task.terminationStatus, output: snapshot.data)
    }
    return forcedTermination ? nil : BoundedCommandResult(terminationStatus: task.terminationStatus, output: Data())
}

private struct SystemRouteExecutor: RouteExecuting {
    func inspect(
        cidrs: [String],
        interfaceName: String,
        trustedMihomoInterfaces: [String]
    ) -> [String: RouteInspection]? {
        inspectSystemRoutes(
            cidrs: cidrs,
            interfaceName: interfaceName,
            trustedMihomoInterfaces: trustedMihomoInterfaces
        )
    }

    func mutate(action: String, cidr: String, interfaceName: String) -> Bool {
        guard action == "add" || action == "delete", validCIDR(cidr), validInterface(interfaceName) else { return false }
        var arguments = ["-n", action]
        if cidr.contains(":") { arguments.append("-inet6") }
        arguments += ["-net", cidr, "-interface", interfaceName]
        return runBoundedCommand(executable: "/sbin/route", arguments: arguments, captureOutput: false)?.terminationStatus == 0
    }
}

private struct ParsedRouteNetwork {
    let bytes: [UInt8]
    let prefix: Int
    let ipv4: Bool
}

private struct RouteTableEntry {
    let network: ParsedRouteNetwork
    let interfaceName: String
}

private func parseRouteNetwork(_ rawValue: String) -> ParsedRouteNetwork? {
    let raw = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !raw.isEmpty, raw != "default" else { return nil }
    let pieces = raw.split(separator: "/", omittingEmptySubsequences: false)
    guard pieces.count <= 2 else { return nil }
    let rawAddress = String(pieces[0])
    let explicitPrefix: Int?
    if pieces.count == 2 {
        guard let parsed = Int(pieces[1]) else { return nil }
        explicitPrefix = parsed
    } else {
        explicitPrefix = nil
    }
    if rawAddress.contains(":") {
        let address = rawAddress.split(separator: "%", maxSplits: 1).first.map(String.init) ?? rawAddress
        var value = in6_addr()
        guard inet_pton(AF_INET6, address, &value) == 1 else { return nil }
        let prefix = explicitPrefix ?? 128
        guard (0...128).contains(prefix) else { return nil }
        let bytes = withUnsafeBytes(of: value) { Array($0) }
        return ParsedRouteNetwork(bytes: bytes, prefix: prefix, ipv4: false)
    }

    let octets = rawAddress.split(separator: ".", omittingEmptySubsequences: false)
    guard (1...4).contains(octets.count), octets.allSatisfy({ UInt8($0) != nil }) else { return nil }
    let padded = octets.map(String.init) + Array(repeating: "0", count: 4 - octets.count)
    var value = in_addr()
    guard inet_pton(AF_INET, padded.joined(separator: "."), &value) == 1 else { return nil }
    let prefix = explicitPrefix ?? octets.count * 8
    guard (0...32).contains(prefix) else { return nil }
    let bytes = withUnsafeBytes(of: value) { Array($0) }
    return ParsedRouteNetwork(bytes: bytes, prefix: prefix, ipv4: true)
}

private func networksOverlap(_ lhs: ParsedRouteNetwork, _ rhs: ParsedRouteNetwork) -> Bool {
    guard lhs.ipv4 == rhs.ipv4, lhs.bytes.count == rhs.bytes.count else { return false }
    var remaining = min(lhs.prefix, rhs.prefix)
    var index = 0
    while remaining > 0 {
        let comparedBits = min(remaining, 8)
        let mask: UInt8 = comparedBits == 8 ? .max : UInt8.max << (8 - comparedBits)
        if lhs.bytes[index] & mask != rhs.bytes[index] & mask { return false }
        remaining -= comparedBits
        index += 1
    }
    return true
}

private func isCanonicalNetwork(_ network: ParsedRouteNetwork) -> Bool {
    let totalBits = network.ipv4 ? 32 : 128
    guard network.prefix <= totalBits else { return false }
    var remaining = totalBits - network.prefix
    var index = network.prefix / 8
    if remaining > 0, network.prefix % 8 != 0 {
        let hostBits = 8 - (network.prefix % 8)
        let hostMask = UInt8((1 << hostBits) - 1)
        guard network.bytes[index] & hostMask == 0 else { return false }
        remaining -= hostBits
        index += 1
    }
    while remaining >= 8 {
        guard network.bytes[index] == 0 else { return false }
        remaining -= 8
        index += 1
    }
    return true
}

private func canonicalAddressString(_ network: ParsedRouteNetwork) -> String? {
    let expectedBytes = network.ipv4 ? MemoryLayout<in_addr>.size : MemoryLayout<in6_addr>.size
    guard network.bytes.count == expectedBytes else { return nil }
    var output = [CChar](
        repeating: 0,
        count: network.ipv4 ? Int(INET_ADDRSTRLEN) : Int(INET6_ADDRSTRLEN)
    )
    if network.ipv4 {
        var address = in_addr()
        withUnsafeMutableBytes(of: &address) { destination in
            destination.copyBytes(from: network.bytes)
        }
        guard inet_ntop(AF_INET, &address, &output, socklen_t(output.count)) != nil else {
            return nil
        }
    } else {
        var address = in6_addr()
        withUnsafeMutableBytes(of: &address) { destination in
            destination.copyBytes(from: network.bytes)
        }
        guard inet_ntop(AF_INET6, &address, &output, socklen_t(output.count)) != nil else {
            return nil
        }
    }
    return String(cString: output)
}

private func isUnspecifiedOrMulticast(_ network: ParsedRouteNetwork) -> Bool {
    let allZero = network.bytes.allSatisfy { $0 == 0 }
    let multicast = network.ipv4 ? network.bytes.first.map { $0 >= 224 } == true : network.bytes.first == 0xff
    return allZero || multicast
}

private func routeConflicts(
    target: ParsedRouteNetwork,
    existing: ParsedRouteNetwork,
    existingInterface: String? = nil,
    trustedMihomoInterfaces: [String] = []
) -> Bool {
    guard existing.prefix > 0, networksOverlap(target, existing) else { return false }
    if existing.prefix < target.prefix,
       let existingInterface,
       trustedMihomoInterfaces.contains(existingInterface) {
        return false
    }
    return true
}

private func networksEqual(_ lhs: ParsedRouteNetwork, _ rhs: ParsedRouteNetwork) -> Bool {
    lhs.ipv4 == rhs.ipv4 && lhs.prefix == rhs.prefix && networksOverlap(lhs, rhs)
}

private func parseRouteTable(_ text: String) -> [RouteTableEntry]? {
    var foundHeader = false
    var entries = [RouteTableEntry]()
    for rawLine in text.components(separatedBy: .newlines) {
        let columns = rawLine.split(whereSeparator: \.isWhitespace)
        if columns.isEmpty { continue }
        if !foundHeader {
            if columns.first == "Destination" {
                guard columns.contains("Netif") else { return nil }
                foundHeader = true
            }
            continue
        }
        let destination = String(columns[0])
        if destination == "default" { continue }
        guard columns.count >= 4,
              let network = parseRouteNetwork(destination)
        else { return nil }
        let interfaceName = String(columns[3])
        guard !interfaceName.isEmpty, interfaceName.utf8.allSatisfy({ byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
                || byte == 45 || byte == 46 || byte == 95
        }) else { return nil }
        entries.append(RouteTableEntry(network: network, interfaceName: interfaceName))
    }
    return foundHeader ? entries : nil
}

private func routeTableEntries(family: String) -> [RouteTableEntry]? {
    guard let result = runBoundedCommand(
        executable: "/usr/sbin/netstat",
        arguments: ["-rn", "-f", family],
        captureOutput: true
    ), result.terminationStatus == 0,
          let text = String(data: result.output, encoding: .utf8)
    else { return nil }
    return parseRouteTable(text)
}

private func inspectRoutes(
    targets: [String: ParsedRouteNetwork],
    interfaceName: String,
    entries: [RouteTableEntry],
    trustedMihomoInterfaces: [String]
) -> [String: RouteInspection] {
    targets.mapValues { target in
        var ownedExact = false
        var foreignConflict = false
        for entry in entries where routeConflicts(
            target: target,
            existing: entry.network,
            existingInterface: entry.interfaceName,
            trustedMihomoInterfaces: trustedMihomoInterfaces
        ) {
            if networksEqual(target, entry.network), entry.interfaceName == interfaceName {
                ownedExact = true
            } else {
                foreignConflict = true
            }
        }
        return RouteInspection(ownedExact: ownedExact, foreignConflict: foreignConflict)
    }
}

private func inspectSystemRoutes(
    cidrs: [String],
    interfaceName: String,
    trustedMihomoInterfaces: [String] = []
) -> [String: RouteInspection]? {
    guard validInterface(interfaceName) else { return nil }
    if cidrs.isEmpty { return [:] }
    var targets = [String: ParsedRouteNetwork]()
    for cidr in cidrs {
        guard validCIDR(cidr), let network = parseRouteNetwork(cidr) else { return nil }
        targets[cidr] = network
    }
    var entries = [RouteTableEntry]()
    if targets.values.contains(where: \.ipv4) {
        guard let ipv4 = routeTableEntries(family: "inet") else { return nil }
        entries.append(contentsOf: ipv4)
    }
    if targets.values.contains(where: { !$0.ipv4 }) {
        guard let ipv6 = routeTableEntries(family: "inet6") else { return nil }
        entries.append(contentsOf: ipv6)
    }
    return inspectRoutes(
        targets: targets,
        interfaceName: interfaceName,
        entries: entries,
        trustedMihomoInterfaces: trustedMihomoInterfaces
    )
}

private func routeLookupSelfTest() -> Bool {
    let table = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    default            192.168.64.1       UGScg                 en0
    128.0/1            192.168.64.1       UGSc                  en0
    192.0.2            link#11            USc                 utun42
    192.0.2.128/25     192.168.64.1       UGSc                  en0
    192.0.3/24         link#5             UCS                   en0
    """
    guard let entries = parseRouteTable(table), entries.count == 4,
          parseRouteTable("Routing tables\nInternet:\n") == nil,
          parseRouteTable("Destination Gateway Flags Netif\nnot-a-route link#1 UCS en0\n") == nil,
          let target4 = parseRouteNetwork("192.0.2.0/24"),
          let target6 = parseRouteNetwork("fd00:64::/48"),
          let moreSpecific6 = parseRouteNetwork("fd00:64:0:1::/64"),
          let lessSpecific6 = parseRouteNetwork("fd00::/8"),
          let disjoint6 = parseRouteNetwork("fd00:65::/64")
    else { return false }
    let inspected = inspectRoutes(
        targets: ["192.0.2.0/24": target4],
        interfaceName: "utun42",
        entries: entries,
        trustedMihomoInterfaces: []
    )
    guard inspected["192.0.2.0/24"]?.ownedExact == true,
          inspected["192.0.2.0/24"]?.foreignConflict == true
    else { return false }
    guard routeConflicts(target: target6, existing: moreSpecific6),
          routeConflicts(target: target6, existing: lessSpecific6),
          !routeConflicts(target: target6, existing: disjoint6),
          let lessSpecific4 = parseRouteNetwork("128.0.0.0/1"),
          !routeConflicts(
              target: target4,
              existing: lessSpecific4,
              existingInterface: "utun123",
              trustedMihomoInterfaces: ["utun123"]
          )
    else { return false }

    let trustedBroadTable = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    0.0/1              192.168.64.1       UGSc                  utun123
    """
    guard let trustedEntries = parseRouteTable(trustedBroadTable),
          let targetV4 = parseRouteNetwork("10.64.0.0/16")
    else { return false }
    let trustedInspection = inspectRoutes(
        targets: ["10.64.0.0/16": targetV4],
        interfaceName: "utun42",
        entries: trustedEntries,
        trustedMihomoInterfaces: ["utun123"]
    )
    guard trustedInspection["10.64.0.0/16"]?.isAvailable == true else { return false }

    let mixedForeignTable = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    0.0/1              192.168.64.1       UGSc                  utun123
    0.0/1              192.168.64.1       UGSc                  en0
    """
    guard let mixedEntries = parseRouteTable(mixedForeignTable) else { return false }
    let mixedInspection = inspectRoutes(
        targets: ["10.64.0.0/16": targetV4],
        interfaceName: "utun42",
        entries: mixedEntries,
        trustedMihomoInterfaces: ["utun123"]
    )
    return mixedInspection["10.64.0.0/16"]?.foreignConflict == true
}

private let productionJournalURL = URL(fileURLWithPath: "/Library/Application Support/KyClash/route-lease-v1.plist")
private let productionJournalV3URL = URL(fileURLWithPath: "/Library/Application Support/KyClash/route-lease-v3.plist")
private let maximumJournalBytes = 64 * 1024
private let journalDirectoryPermissions: mode_t = 0o700
private let journalFilePermissions: mode_t = 0o600

private enum JournalReadResult {
    case absent
    case data(Data)
    case invalid
}

private func isProductionJournalURL(_ url: URL) -> Bool {
    let path = url.standardizedFileURL.path
    return path == productionJournalURL.path || path == productionJournalV3URL.path
}

private func lstatResult(_ url: URL) -> (info: stat?, error: Int32) {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { return (nil, errno) }
    return (info, 0)
}

private func lstatInfo(_ url: URL) -> stat? {
    lstatResult(url).info
}

private func isRegularFile(_ info: stat) -> Bool {
    (info.st_mode & S_IFMT) == S_IFREG
}

private func isDirectory(_ info: stat) -> Bool {
    (info.st_mode & S_IFMT) == S_IFDIR
}

private func hasExactPermissions(_ info: stat, _ permissions: mode_t) -> Bool {
    (info.st_mode & 0o777) == permissions
}

private func validateJournalDirectory(_ directory: URL, createIfMissing: Bool) -> Bool {
    if lstatInfo(directory) == nil {
        guard createIfMissing, mkdir(directory.path, journalDirectoryPermissions) == 0 || errno == EEXIST else {
            return false
        }
    }
    guard let info = lstatInfo(directory),
          isDirectory(info),
          hasExactPermissions(info, journalDirectoryPermissions),
          info.st_nlink >= 2
    else { return false }
    if isProductionJournalURL(directory.appendingPathComponent("route-lease-v1.plist"))
        || isProductionJournalURL(directory.appendingPathComponent("route-lease-v3.plist")) {
        guard info.st_uid == 0 else { return false }
    }
    return true
}

private func readAll(_ descriptor: Int32, expectedSize: Int) -> Data? {
    var result = Data(capacity: expectedSize)
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let count = buffer.withUnsafeMutableBytes { bytes in
            Darwin.read(descriptor, bytes.baseAddress, bytes.count)
        }
        if count == 0 { break }
        if count < 0 {
            if errno == EINTR { continue }
            return nil
        }
        result.append(buffer, count: count)
        guard result.count <= maximumJournalBytes else { return nil }
    }
    return result.count == expectedSize ? result : nil
}

private func readJournalData(_ url: URL) -> JournalReadResult {
    let result = lstatResult(url)
    guard let info = result.info else {
        return result.error == ENOENT ? .absent : .invalid
    }
    guard isRegularFile(info),
          info.st_nlink == 1,
          hasExactPermissions(info, journalFilePermissions),
          info.st_size >= 0,
          info.st_size <= off_t(maximumJournalBytes)
    else { return .invalid }
    if isProductionJournalURL(url) {
        guard info.st_uid == 0 else { return .invalid }
    }
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { return .invalid }
    defer { _ = close(descriptor) }
    var openedInfo = stat()
    guard fstat(descriptor, &openedInfo) == 0,
          isRegularFile(openedInfo),
          openedInfo.st_nlink == 1,
          openedInfo.st_size == info.st_size,
          hasExactPermissions(openedInfo, journalFilePermissions)
    else { return .invalid }
    guard let data = readAll(descriptor, expectedSize: Int(openedInfo.st_size)) else { return .invalid }
    var finalInfo = stat()
    guard fstat(descriptor, &finalInfo) == 0, finalInfo.st_size == openedInfo.st_size else { return .invalid }
    return .data(data)
}

private func fsyncDirectory(_ directory: URL) -> Bool {
    let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard descriptor >= 0 else { return false }
    defer { _ = close(descriptor) }
    return fsync(descriptor) == 0
}

private func removeJournalFile(_ url: URL) -> Bool {
    let result = lstatResult(url)
    guard let info = result.info else { return result.error == ENOENT }
    guard isRegularFile(info),
          info.st_nlink == 1,
          hasExactPermissions(info, journalFilePermissions),
          (!isProductionJournalURL(url) || info.st_uid == 0)
    else { return false }
    guard unlink(url.path) == 0 else { return errno == ENOENT }
    return fsyncDirectory(url.deletingLastPathComponent())
}

private func isSymbolicLink(_ url: URL) -> Bool {
    guard let info = lstatInfo(url) else { return false }
    return (info.st_mode & S_IFMT) == S_IFLNK
}

private final class RouteCoordinator {
    static let shared = RouteCoordinator()
    private let lock = NSLock()
    private let executor: RouteExecuting
    private let journalURL: URL
    private let removeJournal: (URL) -> Bool
    private var journal: RouteJournal?
    // A valid v1 journal is recovery-only.  It must never be used to start a
    // new transaction or be rewritten as v2; keep it in memory until the
    // exact-owner rollback succeeds and the original file is removed.
    private var legacyJournal: LegacyRouteJournal?
    private var journalCorrupt = false
    private var lastCompletedReference: LeaseReference?
    // Every accepted XPC connection enters this set before NSXPCConnection is
    // resumed.  Keeping admission, request dispatch, owned rollback, and
    // removal under the same lock makes a sole-caller `idle` reply an
    // authoritative connection barrier instead of a journal-only snapshot.
    private var registeredConnectionIDs = Set<UUID>()
    private var activeConnectionID: UUID?
    private var lastCompletedConnectionID: UUID?
    private var heartbeatDeadline = Date.distantPast
    private var timer: DispatchSourceTimer?

    init(
        executor: RouteExecuting = SystemRouteExecutor(),
        journalURL: URL = URL(fileURLWithPath: "/Library/Application Support/KyClash/route-lease-v1.plist"),
        removeJournal: @escaping (URL) -> Bool = removeJournalFile
    ) {
        self.executor = executor
        self.journalURL = journalURL
        self.removeJournal = removeJournal
        switch readJournalData(journalURL) {
        case .absent:
            break
        case .data(let data):
            do {
                let decoded = try PropertyListDecoder().decode(RouteJournal.self, from: data)
                guard decoded.isValid() else { throw CocoaError(.fileReadCorruptFile) }
                journal = decoded
            } catch {
                do {
                    let legacy = try PropertyListDecoder().decode(LegacyRouteJournal.self, from: data)
                    guard legacy.isValid() else { throw CocoaError(.fileReadCorruptFile) }
                    legacyJournal = legacy
                } catch {
                    journalCorrupt = true
                    journal = nil
                    legacyJournal = nil
                }
            }
        case .invalid:
            journalCorrupt = true
            journal = nil
        }
        // Reconcile a durable transaction before the first XPC request.  The
        // singleton is also eagerly constructed by `main`, so a restart does
        // not leave owned routes behind until a client happens to call
        // `discover`.
        if journal != nil { _ = rollbackLocked() }
        if legacyJournal != nil { _ = rollbackLegacyLocked() }
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in self?.expireLease() }
        timer.resume()
        self.timer = timer
    }

    deinit {
        timer?.setEventHandler {}
        timer?.cancel()
    }

    @discardableResult
    func register(connectionID: UUID) -> Bool {
        lock.withLock { registeredConnectionIDs.insert(connectionID).inserted }
    }

    func discover(
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID) else { return ownershipFailure() }
            guard registeredConnectionIDs.count == 1 else {
                return HelperReply(state: "failed_closed", errorCode: "not_ready")
            }
            if journalCorrupt { return HelperReply(state: "failed_closed", errorCode: "journal_corrupt") }
            if legacyJournal != nil {
                return HelperReply(state: "failed_closed", errorCode: "recovery_required")
            }
            if journal != nil || activeConnectionID != nil {
                return HelperReply(state: "failed_closed", errorCode: "recovery_required")
            }
            return HelperReply(state: "idle")
        }
    }

    func begin(
        _ owner: LeaseOwner,
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID) else { return ownershipFailure() }
            guard !journalCorrupt,
                  legacyJournal == nil,
                  activeConnectionID == nil,
                  owner.isValid(),
                  journal == nil else {
                return HelperReply(
                    state: "failed_closed",
                    errorCode: legacyJournal != nil ? "recovery_required" : "invalid_owner"
                )
            }
            guard let inspections = executor.inspect(
                cidrs: owner.privateCIDRs,
                interfaceName: owner.interfaceName,
                trustedMihomoInterfaces: owner.activeMihomoTunInterfaces
            ),
                  owner.privateCIDRs.allSatisfy({ inspections[$0]?.isAvailable == true })
            else {
                return HelperReply(state: "failed_closed", errorCode: "route_conflict")
            }
            let candidate = RouteJournal(version: protocolVersion, owner: JournalOwner(owner), pendingCIDR: nil, appliedCIDRs: [])
            guard persist(candidate) else { return HelperReply(state: "failed_closed", errorCode: "journal_write_failed") }
            journal = candidate
            activeConnectionID = connectionID
            lastCompletedReference = nil
            lastCompletedConnectionID = nil
            heartbeatDeadline = Date().addingTimeInterval(15)
            return HelperReply(state: "prepared")
        }
    }

    func apply(
        _ reference: LeaseReference,
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID),
                  ownsConnection(connectionID),
                  valid(reference),
                  var current = journal else {
                return ownershipFailure()
            }
            let remaining = current.owner.privateCIDRs.filter { !current.appliedCIDRs.contains($0) }
            if !remaining.isEmpty {
                guard let preflight = executor.inspect(
                    cidrs: remaining,
                    interfaceName: current.owner.interfaceName,
                    trustedMihomoInterfaces: current.owner.activeMihomoTunInterfaces
                ),
                      remaining.allSatisfy({ preflight[$0]?.isAvailable == true })
                else {
                    let cleaned = rollbackLocked()
                    return HelperReply(state: "failed_closed", errorCode: cleaned ? "route_conflict" : "rollback_failed")
                }
            }
            for cidr in current.owner.privateCIDRs where !current.appliedCIDRs.contains(cidr) {
                current.pendingCIDR = cidr
                guard persist(current) else {
                    let cleaned = rollbackLocked()
                    return HelperReply(state: "failed_closed", errorCode: cleaned ? "journal_write_failed" : "rollback_failed")
                }
                journal = current
                guard executor.mutate(action: "add", cidr: cidr, interfaceName: current.owner.interfaceName) else {
                    journal = current
                    let cleaned = rollbackLocked()
                    return HelperReply(state: "failed_closed", errorCode: cleaned ? "route_apply_failed" : "rollback_failed")
                }
                current.appliedCIDRs.append(cidr)
                current.pendingCIDR = nil
                guard persist(current) else {
                    journal = current
                    let cleaned = rollbackLocked()
                    return HelperReply(state: "failed_closed", errorCode: cleaned ? "journal_write_failed" : "rollback_failed")
                }
                journal = current
            }
            guard let postflight = executor.inspect(
                cidrs: current.owner.privateCIDRs,
                interfaceName: current.owner.interfaceName,
                trustedMihomoInterfaces: current.owner.activeMihomoTunInterfaces
            ),
                  current.owner.privateCIDRs.allSatisfy({
                      postflight[$0]?.ownedExact == true && postflight[$0]?.foreignConflict == false
                  })
            else {
                let cleaned = rollbackLocked()
                return HelperReply(state: "failed_closed", errorCode: cleaned ? "route_conflict" : "rollback_failed")
            }
            return HelperReply(state: "applied")
        }
    }

    func rollback(
        _ reference: LeaseReference,
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID) else { return ownershipFailure() }
            if journal == nil,
               lastCompletedConnectionID == connectionID,
               lastCompletedReference.map({ referencesEqual($0, reference) }) == true {
                return HelperReply(state: "idle")
            }
            guard ownsConnection(connectionID), valid(reference) else { return ownershipFailure() }
            return rollbackLocked() ? HelperReply(state: "idle") : HelperReply(state: "failed_closed", errorCode: "rollback_failed")
        }
    }

    func recover(
        _ owner: LeaseOwner,
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID) else { return ownershipFailure() }
            if legacyJournal != nil {
                return HelperReply(state: "failed_closed", errorCode: "recovery_required")
            }
            guard !journalCorrupt,
                  activeConnectionID == connectionID,
                  owner.isValid(),
                  let journal,
                  journal.owner == JournalOwner(owner),
                  journal.isValid()
            else { return HelperReply(state: "failed_closed", errorCode: "ownership_mismatch") }
            let live = statusLocked()
            guard live.errorCode == nil else { return live }
            activeConnectionID = connectionID
            heartbeatDeadline = Date().addingTimeInterval(15)
            return live
        }
    }

    func heartbeat(
        _ reference: LeaseReference,
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID) else { return ownershipFailure() }
            if legacyJournal != nil {
                return HelperReply(state: "failed_closed", errorCode: "recovery_required")
            }
            guard ownsConnection(connectionID), valid(reference) else { return ownershipFailure() }
            heartbeatDeadline = Date().addingTimeInterval(15)
            return statusLocked()
        }
    }

    func status(
        _ reference: LeaseReference,
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID) else { return ownershipFailure() }
            if legacyJournal != nil {
                return HelperReply(state: "failed_closed", errorCode: "recovery_required")
            }
            return ownsConnection(connectionID) && valid(reference) ? statusLocked() : ownershipFailure()
        }
    }

    @discardableResult
    func unregister(
        connectionID: UUID = coordinatorSelfTestConnectionID
    ) -> HelperReply {
        lock.withLock {
            guard isRegistered(connectionID) else { return ownershipFailure() }

            // Removal is deliberately after the exact connection's owned
            // rollback attempt.  A concurrently polling replacement therefore
            // observes `not_ready` until cleanup has completed under this same
            // lock.  On failure, the durable journal remains authoritative and
            // discovery returns recovery_required rather than transient idle.
            let ownsLease = activeConnectionID == connectionID
            let rolledBack = !ownsLease || rollbackLocked()
            if ownsLease, rolledBack { activeConnectionID = nil }
            registeredConnectionIDs.remove(connectionID)

            guard rolledBack else {
                return HelperReply(state: "failed_closed", errorCode: "rollback_failed")
            }
            if journalCorrupt {
                return HelperReply(state: "failed_closed", errorCode: "journal_corrupt")
            }
            if legacyJournal != nil || journal != nil || activeConnectionID != nil {
                return HelperReply(state: "failed_closed", errorCode: "recovery_required")
            }
            return HelperReply(state: "idle")
        }
    }

    // Test-only trigger used by the no-privilege coordinator matrix.  It
    // drives the same lease-expiry path as the timer without sleeping for the
    // production 15-second heartbeat window.
    func expireLeaseForSelfTest() {
        lock.withLock { heartbeatDeadline = .distantPast }
        expireLease()
    }

    private func statusLocked() -> HelperReply {
        guard let journal else { return HelperReply(state: "idle") }
        guard journal.isValid(),
              let inspections = executor.inspect(
                  cidrs: journal.owner.privateCIDRs,
                  interfaceName: journal.owner.interfaceName,
                  trustedMihomoInterfaces: journal.owner.activeMihomoTunInterfaces
              )
        else {
            return HelperReply(state: "failed_closed", errorCode: "recovery_required")
        }

        let applied = Set(journal.appliedCIDRs)
        let allRoutesOwned = journal.owner.privateCIDRs.allSatisfy { cidr in
            guard let inspection = inspections[cidr], !inspection.foreignConflict else { return false }
            if applied.contains(cidr) {
                return inspection.ownedExact
            }
            return !inspection.ownedExact
        }
        guard allRoutesOwned else {
            return HelperReply(state: "failed_closed", errorCode: "recovery_required")
        }
        let complete = journal.pendingCIDR == nil && applied.count == journal.owner.privateCIDRs.count
        return HelperReply(state: complete ? "applied" : "prepared")
    }

    private func valid(_ reference: LeaseReference) -> Bool {
        reference.isValid() && reference.leaseID == journal?.owner.leaseID && reference.operationID == journal?.owner.operationID
    }

    private func ownsConnection(_ connectionID: UUID) -> Bool {
        activeConnectionID == connectionID
    }

    private func isRegistered(_ connectionID: UUID) -> Bool {
        registeredConnectionIDs.contains(connectionID)
    }

    private func ownershipFailure() -> HelperReply { HelperReply(state: "failed_closed", errorCode: "ownership_mismatch") }

    private func expireLease() {
        lock.withLock {
            guard Date() > heartbeatDeadline else { return }
            if journal != nil {
                _ = rollbackLocked()
            } else if legacyJournal != nil {
                _ = rollbackLegacyLocked()
            } else {
                activeConnectionID = nil
            }
        }
    }

    private func rollbackLocked() -> Bool {
        guard var current = journal else { return true }
        guard current.isValid() else {
            journalCorrupt = true
            return false
        }
        var owned = current.appliedCIDRs
        if let pending = current.pendingCIDR, !owned.contains(pending) { owned.append(pending) }
        guard let inspections = executor.inspect(
            cidrs: owned,
            interfaceName: current.owner.interfaceName,
            trustedMihomoInterfaces: current.owner.activeMihomoTunInterfaces
        ),
              owned.allSatisfy({ inspections[$0] != nil })
        else {
            return false
        }
        for cidr in owned.reversed() {
            // Keep pending disjoint from applied.  The durable state below
            // means "this CIDR is the one being deleted"; a crash can safely
            // recover it through the pending list without pretending the
            // deletion has already committed.
            var pendingState = current
            pendingState.appliedCIDRs.removeAll { $0 == cidr }
            pendingState.pendingCIDR = cidr
            guard pendingState.isValid(), persist(pendingState) else {
                // Keep the unresolved pending marker in memory and stop.  A
                // later route must not overwrite it when the durable write
                // itself failed.
                journal = current
                return false
            }
            current = pendingState
            journal = current
            // Re-read immediately after the durable pending marker.  The
            // initial batch snapshot is only a preflight; another route owner
            // may have changed the table while the journal was being written.
            // Never make a delete decision from that stale snapshot.
            guard let freshInspections = executor.inspect(
                cidrs: [cidr],
                interfaceName: current.owner.interfaceName,
                trustedMihomoInterfaces: current.owner.activeMihomoTunInterfaces
            ), let inspection = freshInspections[cidr] else {
                journal = current
                return false
            }
            let ownedExact = inspection.ownedExact
            let foreignConflict = inspection.foreignConflict
            if !ownedExact && foreignConflict {
                // A foreign overlap without an exact route on our interface
                // is ambiguous; never erase the journal as if ownership were
                // proven absent.
                journal = current
                return false
            }
            if ownedExact,
               !executor.mutate(action: "delete", cidr: cidr, interfaceName: current.owner.interfaceName) {
                // The pending marker has already been persisted, so retain it
                // for a deterministic retry instead of moving on and hiding
                // the failed deletion behind a later CIDR.
                journal = current
                return false
            }
            guard let afterDelete = executor.inspect(
                cidrs: [cidr],
                interfaceName: current.owner.interfaceName,
                trustedMihomoInterfaces: current.owner.activeMihomoTunInterfaces
            ), let afterDeleteEntry = afterDelete[cidr],
                  !afterDeleteEntry.ownedExact,
                  !afterDeleteEntry.foreignConflict else {
                // The durable pending state was never cleared, so a failed or
                // ambiguous postflight remains recoverable without another
                // best-effort journal write.
                journal = pendingState
                return false
            }
            current.pendingCIDR = nil
            guard persist(current) else {
                // Keep the pre-delete durable state, including the pending
                // marker. A later retry can prove the route absent and then
                // commit the cleared state.
                journal = pendingState
                return false
            }
            journal = current
        }
        guard removeJournal(journalURL) else {
            journal = current
            return false
        }
        lastCompletedReference = LeaseReference(
            version: protocolVersion,
            leaseID: current.owner.leaseID,
            operationID: current.owner.operationID
        )
        lastCompletedConnectionID = activeConnectionID
        journal = nil
        activeConnectionID = nil
        heartbeatDeadline = .distantPast
        return true
    }

    // A v1 journal is a rollback-only compatibility record.  It cannot be
    // adopted as a v2 lease because it has no typed Mihomo interface or tunnel
    // family facts.  We therefore use the old owner tuple only to prove the
    // exact interface/CIDR deletion, persist progress in the original v1
    // schema, and remove the file only after every owned exact route is absent.
    // A foreign overlap is never deleted and keeps recovery required.
    private func rollbackLegacyLocked() -> Bool {
        guard var current = legacyJournal else { return true }
        guard current.isValid() else {
            journalCorrupt = true
            return false
        }

        var owned = current.appliedCIDRs
        if let pending = current.pendingCIDR, !owned.contains(pending) { owned.append(pending) }
        var seen = Set<String>()
        owned = owned.filter { seen.insert($0).inserted }
        guard let inspections = executor.inspect(
            cidrs: owned,
            interfaceName: current.owner.interfaceName,
            trustedMihomoInterfaces: []
        ), owned.allSatisfy({ inspections[$0] != nil }) else {
            return false
        }

        for cidr in owned.reversed() {
            var pendingState = current
            pendingState.appliedCIDRs.removeAll { $0 == cidr }
            pendingState.pendingCIDR = cidr
            guard pendingState.isValid(), persistLegacy(pendingState) else {
                legacyJournal = current
                return false
            }
            current = pendingState
            legacyJournal = current

            guard let fresh = executor.inspect(
                cidrs: [cidr],
                interfaceName: current.owner.interfaceName,
                trustedMihomoInterfaces: []
            ), let inspection = fresh[cidr] else {
                return false
            }
            if !inspection.ownedExact && inspection.foreignConflict {
                // We cannot establish that the route belongs to this legacy
                // lease.  Leave the pending marker for an explicit retry.
                return false
            }
            if inspection.ownedExact,
               !executor.mutate(action: "delete", cidr: cidr, interfaceName: current.owner.interfaceName) {
                return false
            }

            guard let afterDelete = executor.inspect(
                cidrs: [cidr],
                interfaceName: current.owner.interfaceName,
                trustedMihomoInterfaces: []
            ), let afterDeleteEntry = afterDelete[cidr],
                  !afterDeleteEntry.ownedExact,
                  !afterDeleteEntry.foreignConflict else {
                legacyJournal = pendingState
                return false
            }
            current.pendingCIDR = nil
            guard persistLegacy(current) else {
                legacyJournal = pendingState
                return false
            }
            legacyJournal = current
        }

        guard removeJournal(journalURL) else { return false }
        legacyJournal = nil
        activeConnectionID = nil
        heartbeatDeadline = .distantPast
        return true
    }

    private func persistLegacy(_ value: LegacyRouteJournal) -> Bool {
        let directory = journalURL.deletingLastPathComponent()
        guard value.isValid(),
              validateJournalDirectory(directory, createIfMissing: true),
              !isSymbolicLink(journalURL),
              let data = try? PropertyListEncoder().encode(value),
              data.count <= maximumJournalBytes else { return false }

        let temporary = directory.appendingPathComponent(
            ".route-lease-v1-legacy.\(UUID().uuidString).tmp"
        )
        let descriptor = open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            journalFilePermissions
        )
        guard descriptor >= 0 else { return false }
        var committed = false
        defer {
            _ = close(descriptor)
            if !committed { _ = unlink(temporary.path) }
        }
        guard fchmod(descriptor, journalFilePermissions) == 0 else { return false }
        var offset = 0
        let writeSucceeded = data.withUnsafeBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else { return data.isEmpty }
            while offset < data.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard writeSucceeded, offset == data.count, fsync(descriptor) == 0,
              rename(temporary.path, journalURL.path) == 0,
              fsyncDirectory(directory),
              let info = lstatInfo(journalURL),
              isRegularFile(info),
              info.st_nlink == 1,
              hasExactPermissions(info, journalFilePermissions),
              (!isProductionJournalURL(journalURL) || info.st_uid == 0) else { return false }
        committed = true
        return true
    }

    private func persist(_ value: RouteJournal) -> Bool {
        let directory = journalURL.deletingLastPathComponent()
        guard value.isValid(),
              validateJournalDirectory(directory, createIfMissing: true),
              !isSymbolicLink(journalURL)
        else { return false }
        guard let data = try? PropertyListEncoder().encode(value), data.count <= maximumJournalBytes else {
            return false
        }

        // Create the replacement in the same directory with O_EXCL and
        // O_NOFOLLOW, write it completely, and fsync both file and directory
        // before accepting the journal as durable.  UUID names avoid a
        // caller-controlled temporary path and the final rename is atomic.
        let temporary = directory.appendingPathComponent(
            ".route-lease-v1.\(UUID().uuidString).tmp"
        )
        let descriptor = open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            journalFilePermissions
        )
        guard descriptor >= 0 else { return false }
        var committed = false
        defer {
            _ = close(descriptor)
            if !committed { _ = unlink(temporary.path) }
        }
        guard fchmod(descriptor, journalFilePermissions) == 0 else { return false }
        var offset = 0
        let writeSucceeded = data.withUnsafeBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else { return data.isEmpty }
            while offset < data.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard writeSucceeded, offset == data.count, fsync(descriptor) == 0 else { return false }
        guard rename(temporary.path, journalURL.path) == 0,
              fsyncDirectory(directory),
              let info = lstatInfo(journalURL),
              isRegularFile(info),
              info.st_nlink == 1,
              hasExactPermissions(info, journalFilePermissions),
              (!isProductionJournalURL(journalURL) || info.st_uid == 0)
        else { return false }
        committed = true
        return true
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T { lock(); defer { unlock() }; return body() }
}

private final class RouteHelperService: NSObject, RouteHelperProtocol {
    private let connectionID: UUID
    private let clientIdentity: ClientAuditIdentity
    private let lifecycleLock = NSLock()
    private var connectionActive = true

    init(connectionID: UUID, clientIdentity: ClientAuditIdentity) {
        self.connectionID = connectionID
        self.clientIdentity = clientIdentity
        super.init()
        routeHelperLogger.notice(
            "accepted client pid=\(clientIdentity.processID, privacy: .public) audit_session=\(clientIdentity.auditSessionID, privacy: .public)"
        )
    }

    deinit {
        invalidateConnection()
    }

    private func activeReply(_ body: () -> HelperReply) -> HelperReply {
        lifecycleLock.withLock {
            guard connectionActive else {
                return HelperReply(state: "failed_closed", errorCode: "ownership_mismatch")
            }
            return body()
        }
    }

    func discover(reply: @escaping (HelperReply) -> Void) {
        reply(activeReply { RouteCoordinator.shared.discover(connectionID: connectionID) })
    }

    func begin(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void) {
        reply(activeReply { RouteCoordinator.shared.begin(owner, connectionID: connectionID) })
    }

    func apply(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(activeReply { RouteCoordinator.shared.apply(reference, connectionID: connectionID) })
    }

    func rollback(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(activeReply { RouteCoordinator.shared.rollback(reference, connectionID: connectionID) })
    }

    func recover(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void) {
        reply(activeReply { RouteCoordinator.shared.recover(owner, connectionID: connectionID) })
    }

    func heartbeat(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(activeReply { RouteCoordinator.shared.heartbeat(reference, connectionID: connectionID) })
    }

    func status(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(activeReply { RouteCoordinator.shared.status(reference, connectionID: connectionID) })
    }

    func invalidateConnection() {
        let invalidated = lifecycleLock.withLock { () -> Bool in
            guard connectionActive else { return false }
            connectionActive = false
            _ = RouteCoordinator.shared.unregister(connectionID: connectionID)
            return true
        }
        guard invalidated else { return }
        routeHelperLogger.notice(
            "closed client pid=\(self.clientIdentity.processID, privacy: .public) audit_session=\(self.clientIdentity.auditSessionID, privacy: .public)"
        )
    }
}

/// Separate v3 service object exported by the production listener. It owns a
/// single coordinator connection and exposes no legacy route surface.
private final class RouteHelperV3Service: NSObject, RouteHelperV3Protocol {
    private let connectionID: UUID
    private let clientIdentity: ClientAuditIdentity
    private let coordinator: RouteHelperV3Coordinator
    private let lifecycleLock = NSLock()
    private var connectionActive = true

    init(
        connectionID: UUID,
        clientIdentity: ClientAuditIdentity,
        coordinator: RouteHelperV3Coordinator
    ) {
        self.connectionID = connectionID
        self.clientIdentity = clientIdentity
        self.coordinator = coordinator
        super.init()
        routeHelperLogger.notice(
            "accepted v3 client pid=\(clientIdentity.processID, privacy: .public) audit_session=\(clientIdentity.auditSessionID, privacy: .public)"
        )
    }

    private func activeReply(_ body: () -> HelperReplyV3) -> HelperReplyV3 {
        lifecycleLock.withLock {
            guard connectionActive else { return v3OwnershipFailure() }
            return body()
        }
    }

    func discoverV3(reply: @escaping (HelperReplyV3) -> Void) {
        reply(activeReply { coordinator.discover(connectionID: connectionID) })
    }

    func beginV3(_ owner: LeaseOwnerV3, reply: @escaping (HelperReplyV3) -> Void) {
        reply(activeReply { coordinator.begin(owner, connectionID: connectionID) })
    }

    func applyV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void) {
        reply(activeReply { coordinator.apply(reference, connectionID: connectionID) })
    }

    func rollbackV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void) {
        reply(activeReply { coordinator.rollback(reference, connectionID: connectionID) })
    }

    func recoverV3(_ owner: LeaseOwnerV3, reply: @escaping (HelperReplyV3) -> Void) {
        reply(activeReply { coordinator.recover(owner, connectionID: connectionID) })
    }

    func heartbeatV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void) {
        reply(activeReply { coordinator.heartbeat(reference, connectionID: connectionID) })
    }

    func statusV3(_ reference: LeaseReferenceV3, reply: @escaping (HelperReplyV3) -> Void) {
        reply(activeReply { coordinator.status(reference, connectionID: connectionID) })
    }

    func invalidateConnection() {
        let shouldInvalidate = lifecycleLock.withLock { () -> Bool in
            guard connectionActive else { return false }
            connectionActive = false
            _ = coordinator.invalidate(connectionID: connectionID)
            return true
        }
        guard shouldInvalidate else { return }
        routeHelperLogger.notice(
            "closed v3 client pid=\(self.clientIdentity.processID, privacy: .public) audit_session=\(self.clientIdentity.auditSessionID, privacy: .public)"
        )
    }
}

private final class RouteHelperV3ListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let coordinator: RouteHelperV3Coordinator

    init(coordinator: RouteHelperV3Coordinator) { self.coordinator = coordinator }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let clientIdentity = ClientAuditIdentity.validated(connection: connection) else {
            routeHelperLogger.error("rejected v3 client with invalid audit identity")
            return false
        }
        connection.setCodeSigningRequirement(appRequirement)
        let connectionID = UUID()
        guard coordinator.register(connectionID: connectionID) else {
            routeHelperLogger.error("rejected duplicate v3 helper connection identity")
            return false
        }
        let service = RouteHelperV3Service(
            connectionID: connectionID,
            clientIdentity: clientIdentity,
            coordinator: coordinator
        )
        connection.exportedInterface = routeHelperV3Interface()
        connection.exportedObject = service
        connection.invalidationHandler = { service.invalidateConnection() }
        connection.interruptionHandler = { service.invalidateConnection() }
        connection.resume()
        return true
    }
}

/// Explicitly gated source/lab listener. It is retained for deterministic
/// interlock experiments, while the signed production helper below always
/// activates the same v3 coordinator without an environment opt-in.
private func runRouteV3LabListener() -> Never {
    guard ProcessInfo.processInfo.environment["KYCLASH_ROUTE_HELPER_V3_LAB"] == "1" else {
        fputs("route_v3_lab_listener_disabled\n", stderr)
        exit(2)
    }
    guard let broker = RootBrokerRouteV3Adapter() else {
        fputs("route_v3_lab_listener_broker_unavailable\n", stderr)
        exit(1)
    }
    let durableStore = DurableRouteJournalV3Store()
    let coordinator = RouteHelperV3Coordinator(
        executor: SystemRouteExecutor(),
        broker: broker,
        store: durableStore
    )
    let startup = coordinator.reconcileStartup()
    guard startup.state == "idle" || startup.state == "released" || startup.state == "recovery_only"
    else {
        fputs("route_v3_lab_listener_recovery_required\n", stderr)
        exit(1)
    }
    // The explicit gate may replace the production process in a lab, so use
    // the locked helper Mach service name expected by the typed Rust client.
    let listener = NSXPCListener(machServiceName: "net.kysion.kyclash.route-helper")
    listener.setConnectionCodeSigningRequirement(appRequirement)
    let delegate = RouteHelperV3ListenerDelegate(coordinator: coordinator)
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
    exit(0)
}

/// Production launch path for the signed SMAppService helper. The durable v3
/// journal is reconciled before accepting the first App connection. A failed
/// reconciliation intentionally leaves the coordinator alive in
/// recovery-only mode so the App receives a typed fail-closed status instead
/// of observing a disappearing Mach service.
private func runRouteV3ProductionListener() -> Never {
    guard let broker = RootBrokerRouteV3Adapter() else {
        fputs("route_v3_production_broker_unavailable\n", stderr)
        exit(1)
    }
    let coordinator = RouteHelperV3Coordinator(
        executor: SystemRouteExecutor(),
        broker: broker,
        store: DurableRouteJournalV3Store()
    )
    let startup = coordinator.reconcileStartup()
    guard startup.isValid() else {
        fputs("route_v3_production_startup_invalid\n", stderr)
        exit(1)
    }
    if startup.state != "idle" {
        routeHelperLogger.warning("v3 helper startup remains (startup.state, privacy: .public)")
    }
    let listener = NSXPCListener(machServiceName: "net.kysion.kyclash.route-helper")
    listener.setConnectionCodeSigningRequirement(appRequirement)
    let delegate = RouteHelperV3ListenerDelegate(coordinator: coordinator)
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
    exit(0)
}

/// Explicit compatibility listener for the legacy v2 coordinator. It is
/// never selected by the signed helper's no-argument launch path; callers
/// must opt in both with the command-line flag and the lab environment gate.
private func runRouteV2LabListener() -> Never {
    guard ProcessInfo.processInfo.environment["KYCLASH_ROUTE_HELPER_V2_LAB"] == "1" else {
        fputs("route_v2_lab_listener_disabled\n", stderr)
        exit(2)
    }
    let listener = NSXPCListener(machServiceName: "net.kysion.kyclash.route-helper")
    listener.setConnectionCodeSigningRequirement(appRequirement)
    let delegate = ListenerDelegate()
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
    exit(0)
}

private final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let clientIdentity = ClientAuditIdentity.validated(connection: connection) else {
            routeHelperLogger.error("rejected client with invalid audit identity")
            return false
        }
        connection.setCodeSigningRequirement(appRequirement)
        let connectionID = UUID()
        guard RouteCoordinator.shared.register(connectionID: connectionID) else {
            routeHelperLogger.error("rejected duplicate helper connection identity")
            return false
        }
        let service = RouteHelperService(connectionID: connectionID, clientIdentity: clientIdentity)
        connection.exportedInterface = routeHelperInterface()
        connection.exportedObject = service
        connection.invalidationHandler = { service.invalidateConnection() }
        connection.interruptionHandler = { service.invalidateConnection() }
        // Registration must happen before resume: a replacement connection
        // can now poll discover without racing an already accepted old
        // connection whose request has not yet reached the coordinator.
        connection.resume()
        return true
    }
}

private func validIdentifier(_ value: String) -> Bool {
    (8...64).contains(value.utf8.count)
        && value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
                || byte == 45 || byte == 46 || byte == 95
        }
}

private func referencesEqual(_ lhs: LeaseReference, _ rhs: LeaseReference) -> Bool {
    lhs.version == rhs.version && lhs.leaseID == rhs.leaseID && lhs.operationID == rhs.operationID
}

private func validUtunInterface(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    guard bytes.count >= 5,
          bytes.count <= maximumDarwinInterfaceBytes,
          bytes.starts(with: Array("utun".utf8))
    else { return false }
    let suffix = bytes.dropFirst(4)
    guard suffix.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return false }
    return suffix.count == 1 || suffix.first != 48
}

private func validCIDR(_ value: String) -> Bool {
    let pieces = value.split(separator: "/", omittingEmptySubsequences: false)
    guard pieces.count == 2,
          !pieces[0].isEmpty,
          !pieces[1].isEmpty,
          value == value.trimmingCharacters(in: .whitespacesAndNewlines),
          !value.contains("%"),
          pieces[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          pieces[1].count == 1 || pieces[1].first != "0",
          UInt8(pieces[1]) != nil
    else { return false }
    guard let network = parseRouteNetwork(value), network.prefix > 0,
          isCanonicalNetwork(network), !isUnspecifiedOrMulticast(network),
          canonicalAddressString(network) == String(pieces[0]),
          String(network.prefix) == pieces[1]
    else { return false }
    return true
}

private func validInterface(_ value: String) -> Bool {
    validUtunInterface(value)
}

// This executor is used only by the explicit local/CI self-test below.  It
// never invokes `/sbin/route`; all mutations stay in memory and can be
// deterministically failed at a selected operation.  Keeping the fault
// injection at the RouteExecuting boundary lets the coordinator exercise the
// same journal/lease/rollback paths as production without touching host
// routes or requiring privileges.
private final class InjectedRouteExecutor: RouteExecuting {
    var existing: Set<String> = []
    var existingRouteInterfaces: [String: String] = [:]
    var added: [String] = []
    var failAddAt: Int?
    var failAddAfterMutationAt: Int?
    var failDeleteAt: Int?
    var failInspectAt: Int?
    private(set) var inspectCalls = 0
    private(set) var addCalls = 0
    private(set) var deleteCalls = 0

    func inspect(
        cidrs: [String],
        interfaceName: String,
        trustedMihomoInterfaces: [String]
    ) -> [String: RouteInspection]? {
        inspectCalls += 1
        if failInspectAt == inspectCalls { return nil }
        guard validInterface(interfaceName), cidrs.allSatisfy(validCIDR) else { return nil }
        return Dictionary(uniqueKeysWithValues: cidrs.map { cidr in
            guard let target = parseRouteNetwork(cidr) else {
                return (cidr, RouteInspection(ownedExact: false, foreignConflict: true))
            }
            let foreignConflict = existing.contains(where: { existingCIDR in
                guard let existingNetwork = parseRouteNetwork(existingCIDR) else { return true }
                let existingInterface = existingRouteInterfaces[existingCIDR] ?? "en0"
                return routeConflicts(
                    target: target,
                    existing: existingNetwork,
                    existingInterface: existingInterface,
                    trustedMihomoInterfaces: trustedMihomoInterfaces
                )
            })
            return (
                cidr,
                RouteInspection(ownedExact: added.contains(cidr), foreignConflict: foreignConflict)
            )
        })
    }

    func mutate(action: String, cidr: String, interfaceName: String) -> Bool {
        guard validCIDR(cidr), validInterface(interfaceName) else { return false }
        switch action {
        case "add":
            defer { addCalls += 1 }
            guard failAddAt != addCalls else { return false }
            added.append(cidr)
            return failAddAfterMutationAt == addCalls ? false : true
        case "delete":
            defer { deleteCalls += 1 }
            guard failDeleteAt != deleteCalls else { return false }
            if let index = added.lastIndex(of: cidr) {
                added.remove(at: index)
                return true
            }
            return !existing.contains(cidr)
        default:
            return false
        }
    }
}

// MARK: - v3 broker/route interlock

// The v3 owner must refresh its lease while a route hold is live. Expiry
// enters the same exact rollback -> journal -> broker-release path used by
// XPC invalidation and startup recovery; it never performs an ad-hoc route
// mutation or clears authority without a durable proof.
private let routeHelperV3HeartbeatExpiry: TimeInterval = 15
private let routeHelperV3HeartbeatWatchdogInterval: TimeInterval = 1

/// The v3 helper coordinator is injected for deterministic tests and is also
/// the coordinator installed by the signed production listener. Its only
/// broker operations are the reviewed typed hold/release/status calls; no
/// path, command, route, or secret can cross this boundary.
private enum RouteBrokerV3Result: Equatable {
    case held
    case released
    case running
    case idle
    /// A typed, validated broker rejection proves that the requested
    /// operation did not acquire/release ownership. It is the only failure
    /// class that may clear a durable HoldPending record.
    case rejected(String)
    /// Transport loss, timeout, interruption, or an unrecognised broker reply
    /// is ambiguous: the remote side may have committed the operation. The
    /// coordinator must retain its journal and recovery authority.
    case ambiguous(String)
}

private protocol RouteBrokerV3Executing: AnyObject {
    func hold(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result
    func release(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result
    func status(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result
}

private enum RouteBrokerV3Operation {
    case hold
    case release
    case status
}

/// Collapse broker-specific failure text into the closed v3 wire vocabulary.
/// The root bridge may have several transport/rejection reasons, but none of
/// those implementation details are safe or stable to expose through XPC.
private func canonicalBrokerV3Error(
    _ reason: String,
    operation: RouteBrokerV3Operation
) -> String {
    _ = reason
    switch operation {
    case .hold:
        return "broker_protocol_failure"
    case .release:
        return "release_failed"
    case .status:
        return "broker_status_failed"
    }
}

private protocol RouteJournalV3Persisting: AnyObject {
    var current: RouteJournalV3? { get }
    var corrupt: Bool { get }
    func persist(_ value: RouteJournalV3) -> Bool
    func remove(_ reference: LeaseReferenceV3) -> Bool
}

private final class InjectedRouteBrokerV3: RouteBrokerV3Executing {
    private(set) var heldReference: LeaseReferenceV3?
    private(set) var releasedReference: LeaseReferenceV3?
    private(set) var knownReference: LeaseReferenceV3?
    private(set) var holdCalls = 0
    private(set) var releaseCalls = 0
    private(set) var statusCalls = 0
    var failHold = false
    var ambiguousHold = false
    var failRelease = false

    func hold(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result {
        holdCalls += 1
        guard reference.isValid() else { return .rejected("invalid_reference") }
        guard !failHold else {
            // The ambiguous fixture records the tuple as if the remote hold
            // committed just before its reply was lost.
            if ambiguousHold { knownReference = reference }
            return ambiguousHold ? .ambiguous("broker_hold_timeout") : .rejected("broker_hold_failed")
        }
        if let knownReference, !referencesEqualV3(knownReference, reference) {
            return .rejected("stale_generation")
        }
        self.knownReference = reference
        if let releasedReference, referencesEqualV3(releasedReference, reference) {
            return .rejected("hold_mismatch")
        }
        if let heldReference {
            return referencesEqualV3(heldReference, reference) ? .held : .rejected("hold_mismatch")
        }
        heldReference = reference
        return .held
    }

    func release(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result {
        releaseCalls += 1
        guard reference.isValid() else { return .rejected("invalid_reference") }
        guard !failRelease else { return .rejected("broker_release_failed") }
        if let releasedReference, referencesEqualV3(releasedReference, reference) {
            return .released
        }
        if let heldReference {
            guard referencesEqualV3(heldReference, reference) else { return .rejected("hold_mismatch") }
            self.heldReference = nil
            releasedReference = reference
            return .released
        }
        // Mirrors the broker's exact current-session no-op release for an
        // ambiguous HoldPending record whose hold never arrived.
        guard let knownReference, referencesEqualV3(knownReference, reference) else {
            return .rejected("hold_mismatch")
        }
        releasedReference = reference
        return .released
    }

    func status(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result {
        statusCalls += 1
        guard reference.isValid() else { return .rejected("invalid_reference") }
        guard let heldReference, referencesEqualV3(heldReference, reference) else {
            return .idle
        }
        return .held
    }
}

/// A small durable-store seam for the coordinator. The injected implementation
/// records every snapshot and can fail a write deterministically; production
/// registration supplies the root-owned atomic file store below.
private final class InjectedRouteJournalV3Store: RouteJournalV3Persisting {
    private(set) var current: RouteJournalV3?
    let corrupt = false
    private(set) var persisted: [RouteJournalV3] = []
    var failPersistAt: Int?
    var failRemove = false
    private(set) var persistCalls = 0

    func persist(_ value: RouteJournalV3) -> Bool {
        persistCalls += 1
        guard value.isValid(), failPersistAt != persistCalls else { return false }
        current = value
        persisted.append(value)
        return true
    }

    func remove(_ reference: LeaseReferenceV3) -> Bool {
        guard !failRemove else { return false }
        guard let current, referencesEqualV3(current.reference(), reference) else { return false }
        self.current = nil
        return true
    }
}

/// Root-owned atomic v3 journal store used by the production listener and the
/// explicit lab listener. It shares the v2 helper's no-symlink,
/// exact-permission, fsync-before-rename discipline, but uses a distinct
/// filename/schema so a v1/v2 record can never be upgraded into a broker-held
/// lease.
private final class DurableRouteJournalV3Store: RouteJournalV3Persisting {
    private let url: URL
    private(set) var current: RouteJournalV3?
    let corrupt: Bool

    init(url: URL = productionJournalV3URL) {
        self.url = url
        switch readJournalData(url) {
        case .absent:
            current = nil
            corrupt = false
        case .data(let data):
            do {
                guard case .currentV3(let journal) = try decodeRouteJournalEnvelope(data),
                      journal.isValid() else {
                    throw RouteJournalDecodeError.corrupt
                }
                current = journal
                corrupt = false
            } catch {
                current = nil
                corrupt = true
            }
        case .invalid:
            current = nil
            corrupt = true
        }
    }

    func persist(_ value: RouteJournalV3) -> Bool {
        guard value.isValid(),
              validateJournalDirectory(url.deletingLastPathComponent(), createIfMissing: true),
              !isSymbolicLink(url),
              let data = try? PropertyListEncoder().encode(value),
              data.count <= maximumJournalBytes else { return false }
        let directory = url.deletingLastPathComponent()
        let temporary = directory.appendingPathComponent(
            ".route-lease-v3.\(UUID().uuidString).tmp"
        )
        let descriptor = open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            journalFilePermissions
        )
        guard descriptor >= 0 else { return false }
        var committed = false
        defer {
            _ = close(descriptor)
            if !committed { _ = unlink(temporary.path) }
        }
        guard fchmod(descriptor, journalFilePermissions) == 0 else { return false }
        var offset = 0
        let writeSucceeded = data.withUnsafeBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else { return data.isEmpty }
            while offset < data.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard writeSucceeded, offset == data.count, fsync(descriptor) == 0,
              rename(temporary.path, url.path) == 0,
              fsyncDirectory(directory),
              let info = lstatInfo(url),
              isRegularFile(info),
              info.st_nlink == 1,
              hasExactPermissions(info, journalFilePermissions),
              (!isProductionJournalURL(url) || info.st_uid == 0) else { return false }
        committed = true
        current = value
        return true
    }

    func remove(_ reference: LeaseReferenceV3) -> Bool {
        guard let current, referencesEqualV3(current.reference(), reference) else { return false }
        // Re-read and decode the exact file immediately before unlinking so a
        // replacement between the last persist and cleanup cannot be removed
        // under an old in-memory owner.
        guard case .data(let data) = readJournalData(url),
              case .currentV3(let onDisk) = try? decodeRouteJournalEnvelope(data),
              onDisk == current,
              referencesEqualV3(onDisk.reference(), reference) else { return false }
        guard removeJournalFile(url) else { return false }
        self.current = nil
        return true
    }
}

/// Implements the locked ordering against injected route and broker seams.
/// The signed helper uses this coordinator as its default listener surface;
/// the legacy v2 coordinator remains available only behind an explicit lab
/// flag for compatibility experiments.
private final class RouteHelperV3Coordinator {
    private let lock = NSLock()
    private let executor: RouteExecuting
    private let broker: RouteBrokerV3Executing
    private let store: RouteJournalV3Persisting
    private var journal: RouteJournalV3?
    private var activeConnectionID: UUID?
    private var registeredConnectionIDs = Set<UUID>()
    private var recoveryOnly = false
    private var heartbeatDeadline = Date.distantPast
    private let heartbeatWatchdogQueue = DispatchQueue(
        label: "net.kysion.kyclash.route-helper.v3-heartbeat",
        qos: .utility
    )
    private var heartbeatWatchdog: DispatchSourceTimer?

    init(
        executor: RouteExecuting,
        broker: RouteBrokerV3Executing,
        store: RouteJournalV3Persisting
    ) {
        self.executor = executor
        self.broker = broker
        self.store = store
        self.journal = store.current
        self.recoveryOnly = store.corrupt
        let timer = DispatchSource.makeTimerSource(queue: heartbeatWatchdogQueue)
        timer.schedule(
            deadline: .now() + routeHelperV3HeartbeatWatchdogInterval,
            repeating: routeHelperV3HeartbeatWatchdogInterval
        )
        timer.setEventHandler { [weak self] in self?.heartbeatWatchdogTick() }
        timer.resume()
        heartbeatWatchdog = timer
    }

    deinit { heartbeatWatchdog?.cancel() }

    private func heartbeatWatchdogTick() {
        lock.withLock {
            guard let journal,
                  journal.state == .holdPending || journal.state == .held || journal.state == .applied,
                  let connectionID = activeConnectionID,
                  Date() >= heartbeatDeadline else { return }
            let reply = retireLocked(journal.reference(), connectionID: connectionID)
            if reply.state != "released" || reply.errorCode != nil {
                // retireLocked already retained the durable journal and set
                // recoveryOnly on every ambiguous/failed boundary.
                recoveryOnly = true
            }
        }
    }

    @discardableResult
    func register(connectionID: UUID) -> Bool {
        lock.withLock {
            // v3 owns one helper connection at a time.  Admission is rejected
            // here (rather than merely returning not_ready from discover) so a
            // second client cannot enqueue requests while the first one still
            // owns a lease or is being invalidated.
            guard registeredConnectionIDs.isEmpty else { return false }
            return registeredConnectionIDs.insert(connectionID).inserted
        }
    }

    func discover(connectionID: UUID) -> HelperReplyV3 {
        lock.withLock {
            guard registeredConnectionIDs.contains(connectionID) else { return v3OwnershipFailure() }
            if recoveryOnly { return HelperReplyV3(state: "recovery_only") }
            guard journal == nil, activeConnectionID == nil else {
                return HelperReplyV3(state: "failed_closed", errorCode: "recovery_required")
            }
            return HelperReplyV3(state: "idle")
        }
    }

    func begin(_ owner: LeaseOwnerV3, connectionID: UUID) -> HelperReplyV3 {
        lock.withLock {
            guard registeredConnectionIDs.contains(connectionID), !recoveryOnly,
                  journal == nil, activeConnectionID == nil, owner.isValid()
            else { return v3OwnershipFailure() }
            guard let inspections = executor.inspect(
                cidrs: owner.privateCIDRs,
                interfaceName: owner.interfaceName,
                trustedMihomoInterfaces: owner.activeMihomoTunInterfaces
            ), owner.privateCIDRs.allSatisfy({ inspections[$0]?.isAvailable == true }) else {
                return HelperReplyV3(state: "failed_closed", errorCode: "route_conflict")
            }

            let pending = RouteJournalV3.holdPending(owner: owner)
            guard store.persist(pending) else {
                return HelperReplyV3(state: "failed_closed", errorCode: "journal_write_failed")
            }
            journal = pending
            activeConnectionID = connectionID
            heartbeatDeadline = Date().addingTimeInterval(routeHelperV3HeartbeatExpiry)

            switch broker.hold(owner.reference) {
            case .held:
                guard let held = try? pending.transitioned(to: .held, reference: owner.reference),
                      store.persist(held) else {
                    recoveryOnly = true
                    return v3Reply(for: pending, errorCode: "journal_write_failed")
                }
                journal = held
                heartbeatDeadline = Date().addingTimeInterval(routeHelperV3HeartbeatExpiry)
                return v3Reply(for: held)
            case .rejected(let reason):
                // Only a typed, definitive rejection may clear HoldPending.
                guard store.remove(owner.reference) else {
                    recoveryOnly = true
                    journal = pending
                    return v3Reply(for: pending, errorCode: "journal_write_failed")
                }
                journal = nil
                activeConnectionID = nil
                heartbeatDeadline = .distantPast
                return HelperReplyV3(
                    state: "failed_closed",
                    errorCode: canonicalBrokerV3Error(reason, operation: .hold)
                )
            case .ambiguous(let reason):
                // A lost/ambiguous reply may follow a committed remote hold.
                // Retain the exact pending tuple and force recovery; never
                // admit a fresh connection while that authority exists.
                recoveryOnly = true
                journal = pending
                return v3Reply(
                    for: pending,
                    errorCode: canonicalBrokerV3Error(reason, operation: .hold)
                )
            default:
                recoveryOnly = true
                return v3Reply(for: pending, errorCode: "broker_protocol_failure")
            }
        }
    }

    func apply(_ reference: LeaseReferenceV3, connectionID: UUID) -> HelperReplyV3 {
        lock.withLock {
            guard registeredConnectionIDs.contains(connectionID), activeConnectionID == connectionID,
                  var current = journal, referencesEqualV3(current.reference(), reference),
                  current.state == .held || current.state == .applied
            else { return v3OwnershipFailure() }
            guard !recoveryOnly else { return HelperReplyV3(state: "recovery_only") }
            if current.state == .applied { return v3Reply(for: current) }

            for cidr in current.owner.privateCIDRs where !current.appliedCIDRs.contains(cidr) {
                current.pendingCIDR = cidr
                guard store.persist(current),
                      executor.mutate(action: "add", cidr: cidr, interfaceName: current.owner.interfaceName),
                      let postflight = executor.inspect(
                          cidrs: [cidr], interfaceName: current.owner.interfaceName,
                          trustedMihomoInterfaces: current.owner.activeMihomoTunInterfaces
                      ), postflight[cidr]?.ownedExact == true,
                      postflight[cidr]?.foreignConflict == false else {
                    journal = current
                    recoveryOnly = true
                    return v3Reply(for: current, errorCode: "route_apply_failed")
                }
                current.appliedCIDRs.append(cidr)
                current.pendingCIDR = nil
                guard store.persist(current) else {
                    journal = current
                    recoveryOnly = true
                    return v3Reply(for: current, errorCode: "journal_write_failed")
                }
                journal = current
            }
            guard let applied = try? current.transitioned(to: .applied, reference: reference),
                  store.persist(applied) else {
                recoveryOnly = true
                journal = current
                return v3Reply(for: current, errorCode: "journal_write_failed")
            }
            journal = applied
            return v3Reply(for: applied)
        }
    }

    func rollback(_ reference: LeaseReferenceV3, connectionID: UUID) -> HelperReplyV3 {
        lock.withLock { retireLocked(reference, connectionID: connectionID) }
    }

    func recover(_ owner: LeaseOwnerV3, connectionID: UUID) -> HelperReplyV3 {
        lock.withLock {
            guard registeredConnectionIDs.contains(connectionID), let journal,
                  journal.owner == JournalOwnerV3(owner),
                  referencesEqualV3(journal.reference(), owner.reference) else {
                return v3OwnershipFailure()
            }
            if activeConnectionID != connectionID {
                guard recoveryOnly || activeConnectionID == nil else { return v3OwnershipFailure() }
                activeConnectionID = connectionID
            }
            return retireLocked(owner.reference, connectionID: connectionID)
        }
    }

    /// Reconcile one durable owner before the listener accepts a new lease.
    /// A failed release leaves `recoveryOnly` set; a later app connection can
    /// call `recover` with the exact owner and no route mutation is replayed.
    func reconcileStartup() -> HelperReplyV3 {
        lock.withLock {
            guard let journal else {
                return recoveryOnly
                    ? HelperReplyV3(state: "recovery_only")
                    : HelperReplyV3(state: "idle")
            }
            let recoveryID = UUID(uuidString: "00000000-0000-4000-8000-000000000008")!
            registeredConnectionIDs.insert(recoveryID)
            activeConnectionID = recoveryID
            let reply = retireLocked(journal.reference(), connectionID: recoveryID)
            registeredConnectionIDs.remove(recoveryID)
            if reply.state != "released" || reply.errorCode != nil {
                recoveryOnly = true
                activeConnectionID = nil
            }
            return reply
        }
    }

    func heartbeat(_ reference: LeaseReferenceV3, connectionID: UUID) -> HelperReplyV3 {
        lock.withLock {
            guard registeredConnectionIDs.contains(connectionID), activeConnectionID == connectionID,
                  let journal, referencesEqualV3(journal.reference(), reference) else {
                return v3OwnershipFailure()
            }
            guard !recoveryOnly else { return HelperReplyV3(state: "recovery_only") }
            return statusWithBrokerLocked(journal)
        }
    }

    func status(_ reference: LeaseReferenceV3, connectionID: UUID) -> HelperReplyV3 {
        lock.withLock {
            guard registeredConnectionIDs.contains(connectionID), let journal,
                  referencesEqualV3(journal.reference(), reference) else {
                return v3OwnershipFailure()
            }
            guard !recoveryOnly else { return HelperReplyV3(state: "recovery_only") }
            return statusWithBrokerLocked(journal)
        }
    }

    private func statusWithBrokerLocked(_ journal: RouteJournalV3) -> HelperReplyV3 {
        guard !recoveryOnly else { return HelperReplyV3(state: "recovery_only") }
        // A Released tombstone has already proved the exact release and is
        // only awaiting unlink; it must not be converted back into a live
        // heartbeat. HoldPending, however, is ambiguous and must query the
        // broker before any heartbeat can extend its deadline.
        if journal.state == .released {
            heartbeatDeadline = .distantPast
            return v3Reply(for: journal)
        }
        guard broker.status(journal.reference()) == .held else {
            recoveryOnly = true
            return v3Reply(
                for: journal,
                errorCode: canonicalBrokerV3Error("status", operation: .status)
            )
        }
        heartbeatDeadline = Date().addingTimeInterval(routeHelperV3HeartbeatExpiry)
        return v3Reply(for: journal)
    }

    func invalidate(connectionID: UUID) -> HelperReplyV3 {
        lock.withLock {
            guard registeredConnectionIDs.remove(connectionID) != nil else { return v3OwnershipFailure() }
            guard let journal, let activeConnectionID, activeConnectionID == connectionID else {
                return HelperReplyV3(state: "idle")
            }
            return retireLocked(journal.reference(), connectionID: connectionID)
        }
    }

    private func retireLocked(_ reference: LeaseReferenceV3, connectionID: UUID) -> HelperReplyV3 {
        guard let current = journal, activeConnectionID == connectionID,
              referencesEqualV3(current.reference(), reference) else {
            if journal == nil { return HelperReplyV3(state: "idle") }
            return v3OwnershipFailure()
        }
        // A durable Released tombstone means the exact broker release already
        // succeeded; only the final journal unlink was lost. Remove that
        // matching file and do not issue a second release or transition back
        // through retirement pending.
        if current.state == .released {
            guard store.remove(reference) else {
                recoveryOnly = true
                return v3Reply(for: current, errorCode: "journal_write_failed")
            }
            journal = nil
            self.activeConnectionID = nil
            heartbeatDeadline = .distantPast
            recoveryOnly = false
            return v3Reply(for: current)
        }
        var mutable = current
        var owned = mutable.appliedCIDRs
        if let pending = mutable.pendingCIDR, !owned.contains(pending) { owned.append(pending) }
        for cidr in owned.reversed() {
            guard let inspection = executor.inspect(
                cidrs: [cidr], interfaceName: mutable.owner.interfaceName,
                trustedMihomoInterfaces: mutable.owner.activeMihomoTunInterfaces
            )?[cidr], !inspection.foreignConflict else {
                recoveryOnly = true
                journal = mutable
                return v3Reply(for: mutable, errorCode: "rollback_failed")
            }
            if inspection.ownedExact {
                // Mark the exact route before mutating the system.  If the
                // helper dies after route deletion (or during deletion), the
                // durable pending marker tells the next recovery pass which
                // operation was in flight instead of presenting a clean
                // applied snapshot.
                mutable.pendingCIDR = cidr
                guard store.persist(mutable) else {
                    recoveryOnly = true
                    journal = mutable
                    return v3Reply(for: mutable, errorCode: "journal_write_failed")
                }
                journal = mutable
            guard executor.mutate(action: "delete", cidr: cidr, interfaceName: mutable.owner.interfaceName),
                  let postflight = executor.inspect(
                      cidrs: [cidr], interfaceName: mutable.owner.interfaceName,
                      trustedMihomoInterfaces: mutable.owner.activeMihomoTunInterfaces
                  ),
                  let postflightEntry = postflight[cidr],
                  !postflightEntry.ownedExact,
                  !postflightEntry.foreignConflict else {
                    recoveryOnly = true
                    journal = mutable
                    return v3Reply(for: mutable, errorCode: "rollback_failed")
                }
            }
            mutable.appliedCIDRs.removeAll { $0 == cidr }
            mutable.pendingCIDR = nil
            guard store.persist(mutable) else {
                recoveryOnly = true
                journal = mutable
                return v3Reply(for: mutable, errorCode: "journal_write_failed")
            }
            journal = mutable
        }

        let retirement: RouteJournalV3
        if mutable.state == .retirementPending {
            retirement = mutable
        } else {
            guard let transitioned = try? mutable.transitioned(to: .retirementPending, reference: reference),
                  store.persist(transitioned) else {
                recoveryOnly = true
                journal = mutable
                return v3Reply(for: mutable, errorCode: "journal_write_failed")
            }
            retirement = transitioned
        }
        guard retirement.isValid() else {
            recoveryOnly = true
            journal = mutable
            return v3Reply(for: mutable, errorCode: "journal_write_failed")
        }
        journal = retirement
        guard case .released = broker.release(reference) else {
            recoveryOnly = true
            return v3Reply(
                for: retirement,
                errorCode: canonicalBrokerV3Error("release", operation: .release)
            )
        }
        guard let released = try? retirement.transitioned(to: .released, reference: reference),
              store.persist(released), store.remove(reference) else {
            recoveryOnly = true
            journal = retirement
            return v3Reply(for: retirement, errorCode: "journal_write_failed")
        }
        journal = nil
        self.activeConnectionID = nil
        heartbeatDeadline = .distantPast
        recoveryOnly = false
        return v3Reply(for: released)
    }

    private func v3Reply(for journal: RouteJournalV3, errorCode: String? = nil) -> HelperReplyV3 {
        HelperReplyV3(
            state: journal.state.rawValue,
            errorCode: errorCode,
            reference: journal.reference(),
            transition: journal.transition
        )
    }
}

private func v3OwnershipFailure() -> HelperReplyV3 {
    HelperReplyV3(state: "failed_closed", errorCode: "ownership_mismatch")
}

/// Production-facing adapter. Construction is fixed to the root broker Mach
/// service and is used by the signed v3 helper listener; no caller-supplied
/// endpoint, command, or route data crosses this boundary.
private final class RootBrokerRouteV3Adapter: RouteBrokerV3Executing {
    private let raw: UnsafeMutableRawPointer

    init?() {
        guard let raw = kyclash_tunnel_broker_route_client_create() else { return nil }
        self.raw = raw
    }

    deinit { kyclash_tunnel_broker_route_client_destroy(raw) }

    func hold(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result {
        let result = call(reference, operation: kyclash_tunnel_broker_route_client_hold)
        guard result.transport_status == 0 else { return .ambiguous("transport_failure") }
        if result.error_code != 0 {
            return result.error_code == 1 || result.error_code == 4 || result.error_code == 5
                || result.error_code == 6 || result.error_code == 7 || result.error_code == 8
                ? .rejected("broker_hold_rejected")
                : .ambiguous("broker_hold_ambiguous")
        }
        return result.state == 2 ? .held : .rejected("broker_hold_rejected")
    }

    func release(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result {
        let result = call(reference, operation: kyclash_tunnel_broker_route_client_release)
        guard result.transport_status == 0 else { return .ambiguous("transport_failure") }
        if result.error_code != 0 {
            return result.error_code == 1 || result.error_code == 4 || result.error_code == 5
                || result.error_code == 6 || result.error_code == 7 || result.error_code == 8
                ? .rejected("broker_release_rejected")
                : .ambiguous("broker_release_ambiguous")
        }
        return (result.state == 0 || result.state == 1) ? .released : .rejected("broker_release_rejected")
    }

    func status(_ reference: LeaseReferenceV3) -> RouteBrokerV3Result {
        let result = call(reference, operation: kyclash_tunnel_broker_route_client_status)
        guard result.transport_status == 0 else { return .ambiguous("transport_failure") }
        if result.error_code != 0 {
            return .ambiguous("broker_status_ambiguous")
        }
        switch result.state {
        case 0: return .idle
        case 1: return .running
        case 2: return .held
        default: return .rejected("broker_status_rejected")
        }
    }

    private typealias Operation = (
        UnsafeMutableRawPointer?, Int32, Int32, UInt64,
        UnsafePointer<CChar>?, UnsafePointer<CChar>?, UnsafePointer<CChar>?
    ) -> KCTBRClientReply

    private func call(_ reference: LeaseReferenceV3, operation: Operation) -> KCTBRClientReply {
        reference.sidecarInstanceID.withCString { sidecar in
            reference.leaseID.withCString { lease in
                reference.operationID.withCString { operationID in
                    operation(
                        raw,
                        Int32(reference.protocolVersion),
                        Int32(reference.brokerProtocolVersion),
                        reference.brokerGeneration,
                        sidecar,
                        lease,
                        operationID
                    )
                }
            }
        }
    }
}

private enum RouteCoordinatorSelfTestError: Error {
    case failed(String)
}

private func requireSelfTest(_ condition: @autoclosure () -> Bool, _ description: String) throws {
    guard condition() else { throw RouteCoordinatorSelfTestError.failed(description) }
}

// The root broker bridge is linked into the helper target. This self-test uses
// a nil client so the helper build proves the exact POD layout and fail-closed
// argument path without contacting a broker or mutating routes; the production
// listener uses the same adapter for typed hold/release/status calls.
private func runRouteV3BridgeSelfTest() -> Bool {
    let result = kyclash_tunnel_broker_route_client_hold(
        nil,
        3,
        1,
        17,
        nil,
        nil,
        nil
    )
    guard result.transport_status == 7,
          result.protocol_version == -1,
          result.broker_protocol_version == -1,
          result.broker_generation == 0,
          result.sidecar_instance_id.0 == 0,
          result.route_lease_id.0 == 0,
          result.operation_id.0 == 0,
          MemoryLayout<KCTBRClientReply>.size >= 8 * MemoryLayout<Int32>.size
    else {
        fputs("route_v3_bridge_self_test_failed\n", stderr)
        return false
    }
    print("route_v3_bridge_self_test_ok")
    return true
}

private func selfTestOwner(
    _ cidrs: [String],
    activeMihomoTunInterfaces: [String] = []
) -> LeaseOwner {
    let reference = LeaseReference(version: protocolVersion, leaseID: "lease.selftest.v1", operationID: "operation.selftest.v1")
    return LeaseOwner(
        reference: reference,
        sidecarInstanceID: "instance.selftest.v1",
        interfaceName: "utun42",
        tunnelOperationID: "operation.selftest.v1.prepare",
        mtu: 1420,
        profileRevision: 1,
        activeMihomoTunInterfaces: activeMihomoTunInterfaces,
        privateCIDRs: cidrs
    )
}

private func selfTestOwnerV3(
    _ cidrs: [String],
    interfaceName: String = "utun42"
) -> LeaseOwnerV3 {
    let reference = LeaseReferenceV3(
        brokerGeneration: 17,
        sidecarInstanceID: "instance.selftest.v3",
        leaseID: "lease.selftest.v3",
        operationID: "operation.selftest.v3"
    )
    return LeaseOwnerV3(
        reference: reference,
        sidecarInstanceID: reference.sidecarInstanceID,
        interfaceName: interfaceName,
        tunnelOperationID: "operation.selftest.v3.prepare",
        mtu: 1420,
        profileRevision: 7,
        activeMihomoTunInterfaces: ["utun1024"],
        privateCIDRs: cidrs
    )
}

private func runRouteV3WireJournalSelfTest() -> Bool {
    do {
        let owner = selfTestOwnerV3(["10.64.0.0/16", "fd00:64::/48"])
        let reference = owner.reference
        try requireSelfTest(reference.isValid(), "v3 reference tuple must validate")
        try requireSelfTest(owner.isValid(), "v3 owner tuple must validate")
        try requireSelfTest(
            selfTestOwnerV3(["10.64.0.0/16"], interfaceName: "utun0").isValid(),
            "utun0 must have the same canonical validity in the v3 owner"
        )

        let archivedOwner = try NSKeyedArchiver.archivedData(
            withRootObject: owner,
            requiringSecureCoding: true
        )
        let decodedOwner = try NSKeyedUnarchiver.unarchivedObject(
            ofClass: LeaseOwnerV3.self,
            from: archivedOwner
        )
        try requireSelfTest(
            decodedOwner?.isValid() == true
                && decodedOwner?.reference.brokerGeneration == 17,
            "v3 owner NSSecureCoding must preserve the complete broker tuple"
        )

        let reply = HelperReplyV3(state: "held", reference: reference, transition: 2)
        try requireSelfTest(reply.isValid(), "v3 exact reply must validate")
        let archivedReply = try NSKeyedArchiver.archivedData(
            withRootObject: reply,
            requiringSecureCoding: true
        )
        let decodedReply = try NSKeyedUnarchiver.unarchivedObject(
            ofClass: HelperReplyV3.self,
            from: archivedReply
        )
        try requireSelfTest(
            decodedReply?.matches(reference, transition: 2) == true,
            "v3 reply decode must echo reference and transition"
        )
        let wrongReplyReference = LeaseReferenceV3(
            brokerGeneration: 18,
            sidecarInstanceID: reference.sidecarInstanceID,
            leaseID: reference.leaseID,
            operationID: reference.operationID
        )
        try requireSelfTest(
            decodedReply?.matches(wrongReplyReference, transition: 2) == false,
            "wrong broker generation in a reply must fail closed"
        )
        let statusFailure = HelperReplyV3(
            state: "retirement_pending",
            errorCode: "broker_status_failed",
            reference: reference,
            transition: 4
        )
        try requireSelfTest(
            statusFailure.isValid(),
            "broker status failure must be a recognized v3 wire error"
        )
        try requireSelfTest(
            !HelperReplyV3(
                state: "failed_closed",
                errorCode: "broker_hold_failed"
            ).isValid(),
            "broker implementation errors must not cross the v3 wire"
        )

        let pending = RouteJournalV3.holdPending(owner: owner)
        try requireSelfTest(
            pending.isValid()
                && pending.state == .holdPending
                && pending.transition == 1
                && pending.appliedCIDRs.isEmpty
                && pending.pendingCIDR == nil
                && !pending.state.permitsFirstRouteMutation,
            "HoldPending must be durable and must not authorize routes"
        )
        let pendingRoundTrip = try PropertyListDecoder().decode(
            RouteJournalV3.self,
            from: PropertyListEncoder().encode(pending)
        )
        try requireSelfTest(pendingRoundTrip == pending, "v3 journal must round-trip strictly")

        let held = try pending.transitioned(to: .held, reference: reference)
        try requireSelfTest(
            held.isValid()
                && held.state == .held
                && held.transition == 2
                && held.state.permitsFirstRouteMutation,
            "Held must be the only state that permits a first route mutation"
        )

        // An Applied record may retain a shrinking exact-owned set while a
        // later cleanup pass is removing routes. It never authorizes a new add.
        var fullyApplied = held
        fullyApplied.appliedCIDRs = owner.privateCIDRs
        let applied = try fullyApplied.transitioned(to: .applied, reference: reference)
        try requireSelfTest(
            applied.isValid()
                && applied.state == .applied
                && applied.transition == 3
                && !applied.state.permitsFirstRouteMutation,
            "Applied must record a held route set without authorizing a new add"
        )

        let retirementFromHold = try held.transitioned(to: .retirementPending, reference: reference)
        try requireSelfTest(
            retirementFromHold.isValid()
                && retirementFromHold.transition == 3
                && retirementFromHold.appliedCIDRs.isEmpty,
            "Held cleanup must support transition-3 RetirementPending"
        )
        let retirementFromApplied = try applied.transitioned(to: .retirementPending, reference: reference)
        try requireSelfTest(
            retirementFromApplied.isValid()
                && retirementFromApplied.transition == 4
                && retirementFromApplied.appliedCIDRs.isEmpty,
            "Applied cleanup must support transition-4 RetirementPending"
        )
        let released = try retirementFromApplied.transitioned(to: .released, reference: reference)
        try requireSelfTest(
            released.isValid()
                && released.transition == 5
                && !released.state.permitsFirstRouteMutation,
            "Released must be terminal and non-mutating"
        )

        let retirementFromPending = try pending.transitioned(to: .retirementPending, reference: reference)
        try requireSelfTest(
            retirementFromPending.transition == 2,
            "ambiguous HoldPending recovery must support transition-2 retirement"
        )
        try requireSelfTest(
            (try? pending.transitioned(to: .applied, reference: reference)) == nil,
            "HoldPending must never jump directly to Applied"
        )
        let replay = RouteJournalTransitionV3(
            protocolVersion: routeHelperV3ProtocolVersion,
            fromState: .holdPending,
            toState: .held,
            transition: 2,
            reference: reference
        )
        try requireSelfTest(
            (try? held.applying(replay)) == nil,
            "a delayed HoldPending reply must be rejected as replay"
        )
        let invalidReleasedReplay = RouteJournalTransitionV3(
            protocolVersion: routeHelperV3ProtocolVersion,
            fromState: .released,
            toState: .released,
            transition: 6,
            reference: reference
        )
        try requireSelfTest(
            (try? released.applying(invalidReleasedReplay)) == nil,
            "Released must reject every replay or transition"
        )

        let v3Data = try PropertyListEncoder().encode(pending)
        switch try decodeRouteJournalEnvelope(v3Data) {
        case .currentV3(let decoded):
            try requireSelfTest(decoded == pending, "version 3 must select the v3 schema")
        case .recoveryOnlyV1, .recoveryOnlyV2:
            throw RouteCoordinatorSelfTestError.failed("v3 journal was classified as legacy")
        }

        let v2Owner = selfTestOwner(["10.64.0.0/16"])
        let v2 = RouteJournal(
            version: protocolVersion,
            owner: JournalOwner(v2Owner),
            pendingCIDR: nil,
            appliedCIDRs: []
        )
        switch try decodeRouteJournalEnvelope(PropertyListEncoder().encode(v2)) {
        case .recoveryOnlyV2:
            break
        case .currentV3, .recoveryOnlyV1:
            throw RouteCoordinatorSelfTestError.failed("v2 journal was not recovery-only")
        }
        let v1 = LegacyRouteJournal(
            version: legacyProtocolVersion,
            owner: LegacyJournalOwner(JournalOwner(v2Owner)),
            pendingCIDR: nil,
            appliedCIDRs: []
        )
        switch try decodeRouteJournalEnvelope(PropertyListEncoder().encode(v1)) {
        case .recoveryOnlyV1:
            break
        case .currentV3, .recoveryOnlyV2:
            throw RouteCoordinatorSelfTestError.failed("v1 journal was not recovery-only")
        }

        func isCorrupt(_ data: Data) -> Bool {
            do {
                _ = try decodeRouteJournalEnvelope(data)
                return false
            } catch RouteJournalDecodeError.corrupt {
                return true
            } catch {
                return false
            }
        }

        func propertyListDictionary(_ data: Data) throws -> [String: Any] {
            var format = PropertyListSerialization.PropertyListFormat.binary
            let object = try PropertyListSerialization.propertyList(
                from: data, options: [], format: &format
            )
            guard let dictionary = object as? [String: Any] else {
                throw RouteCoordinatorSelfTestError.failed("journal plist root was not a dictionary")
            }
            return dictionary
        }

        var unknownTopLevel = try propertyListDictionary(v3Data)
        unknownTopLevel["unexpectedField"] = "reject-me"
        let unknownTopLevelData = try PropertyListSerialization.data(
            fromPropertyList: unknownTopLevel, format: .binary, options: 0
        )
        try requireSelfTest(isCorrupt(unknownTopLevelData), "unknown v3 top-level key must be corrupt")

        var unknownOwner = try propertyListDictionary(v3Data)
        var ownerDictionary = try requireDictionary(unknownOwner["owner"])
        ownerDictionary["command"] = "/sbin/route delete default"
        unknownOwner["owner"] = ownerDictionary
        let unknownOwnerData = try PropertyListSerialization.data(
            fromPropertyList: unknownOwner, format: .binary, options: 0
        )
        try requireSelfTest(isCorrupt(unknownOwnerData), "unknown v3 owner key must be corrupt")

        var crossSchema = try propertyListDictionary(v3Data)
        crossSchema["version"] = 2
        let crossSchemaData = try PropertyListSerialization.data(
            fromPropertyList: crossSchema, format: .binary, options: 0
        )
        try requireSelfTest(isCorrupt(crossSchemaData), "v3 payload under v2 version must be corrupt")

        var unknownVersion = try propertyListDictionary(v3Data)
        unknownVersion["version"] = 99
        let unknownVersionData = try PropertyListSerialization.data(
            fromPropertyList: unknownVersion, format: .binary, options: 0
        )
        try requireSelfTest(isCorrupt(unknownVersionData), "unknown journal version must be corrupt")

        print("route_v3_wire_journal_self_test_ok")
        return true
    } catch {
        fputs("route_v3_wire_journal_self_test_failed: \(error)\n", stderr)
        return false
    }
}

private func runRouteV3InterlockSelfTest() -> Bool {
    do {
        let connectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000003")!
        let owner = selfTestOwnerV3(["10.64.0.0/16", "fd00:64::/48"])
        let executor = InjectedRouteExecutor()
        let broker = InjectedRouteBrokerV3()
        let store = InjectedRouteJournalV3Store()
        let coordinator = RouteHelperV3Coordinator(executor: executor, broker: broker, store: store)
        try requireSelfTest(coordinator.register(connectionID: connectionID), "v3 listener must register one connection")
        let duplicateConnectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000008")!
        try requireSelfTest(
            !coordinator.register(connectionID: duplicateConnectionID),
            "v3 listener must reject a second live connection"
        )
        try requireSelfTest(coordinator.discover(connectionID: connectionID).state == "idle",
                            "v3 discover must start idle")

        let pendingExecutor = InjectedRouteExecutor()
        let pendingBroker = InjectedRouteBrokerV3()
        let pendingStore = InjectedRouteJournalV3Store()
        pendingStore.failPersistAt = 2
        let pendingCoordinator = RouteHelperV3Coordinator(
            executor: pendingExecutor, broker: pendingBroker, store: pendingStore
        )
        let pendingConnectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000007")!
        try requireSelfTest(pendingCoordinator.register(connectionID: pendingConnectionID),
                            "ambiguous-hold connection must register")
        let ambiguousHold = pendingCoordinator.begin(owner, connectionID: pendingConnectionID)
        try requireSelfTest(ambiguousHold.errorCode == "journal_write_failed" && pendingBroker.heldReference != nil,
                            "a lost Held journal write must retain the exact broker hold")
        let ambiguousRecovered = pendingCoordinator.recover(owner, connectionID: pendingConnectionID)
        try requireSelfTest(ambiguousRecovered.state == "released" && pendingBroker.heldReference == nil,
                            "ambiguous HoldPending recovery must release without route mutation")
        try requireSelfTest(pendingExecutor.addCalls == 0,
                            "ambiguous hold recovery must never add a route")

        // If the broker rejects a hold while the pending journal cannot be
        // removed, the helper must retain recovery-only ownership instead of
        // clearing memory and admitting a fresh lease.
        let failedHoldExecutor = InjectedRouteExecutor()
        let failedHoldBroker = InjectedRouteBrokerV3()
        failedHoldBroker.failHold = true
        let failedHoldStore = InjectedRouteJournalV3Store()
        failedHoldStore.failRemove = true
        let failedHold = RouteHelperV3Coordinator(
            executor: failedHoldExecutor, broker: failedHoldBroker, store: failedHoldStore
        )
        let failedHoldConnectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000009")!
        try requireSelfTest(failedHold.register(connectionID: failedHoldConnectionID),
                            "failed-hold connection must register")
        let failedHoldReply = failedHold.begin(owner, connectionID: failedHoldConnectionID)
        try requireSelfTest(
            failedHoldReply.errorCode == "journal_write_failed"
                && failedHoldStore.current?.state == .holdPending
                && failedHold.discover(connectionID: failedHoldConnectionID).state == "recovery_only",
            "failed hold cleanup must retain pending ownership when unlink fails"
        )

        // A lost broker hold reply is ambiguous even when the local journal
        // unlink would succeed. The exact pending tuple remains recovery-only
        // and a fresh connection cannot be admitted until that tuple is
        // explicitly released.
        let lostReplyExecutor = InjectedRouteExecutor()
        let lostReplyBroker = InjectedRouteBrokerV3()
        lostReplyBroker.failHold = true
        lostReplyBroker.ambiguousHold = true
        let lostReplyStore = InjectedRouteJournalV3Store()
        let lostReply = RouteHelperV3Coordinator(
            executor: lostReplyExecutor, broker: lostReplyBroker, store: lostReplyStore
        )
        let lostReplyConnectionID = UUID(uuidString: "00000000-0000-4000-8000-00000000000a")!
        try requireSelfTest(lostReply.register(connectionID: lostReplyConnectionID),
                            "lost-reply connection must register")
        let lostReplyResult = lostReply.begin(owner, connectionID: lostReplyConnectionID)
        try requireSelfTest(
            lostReplyResult.errorCode == "broker_protocol_failure"
                && lostReplyStore.current?.state == .holdPending
                && lostReply.discover(connectionID: lostReplyConnectionID).state == "recovery_only",
            "ambiguous hold reply must retain pending authority and refuse fresh work"
        )
        let pendingHeartbeat = lostReply.heartbeat(owner.reference, connectionID: lostReplyConnectionID)
        try requireSelfTest(
            pendingHeartbeat.state == "recovery_only"
                && lostReply.discover(connectionID: lostReplyConnectionID).state == "recovery_only",
            "recovery-only HoldPending heartbeat must not extend its deadline"
        )
        let stalePendingStore = InjectedRouteJournalV3Store()
        try requireSelfTest(
            stalePendingStore.persist(RouteJournalV3.holdPending(owner: owner)),
            "stale pending fixture must persist"
        )
        let stalePendingBroker = InjectedRouteBrokerV3()
        let stalePending = RouteHelperV3Coordinator(
            executor: InjectedRouteExecutor(), broker: stalePendingBroker, store: stalePendingStore
        )
        let stalePendingConnectionID = UUID(uuidString: "00000000-0000-4000-8000-00000000000e")!
        try requireSelfTest(stalePending.register(connectionID: stalePendingConnectionID),
                            "stale pending status connection must register")
        try requireSelfTest(
            stalePending.status(owner.reference, connectionID: stalePendingConnectionID).state == "recovery_only",
            "HoldPending status must query broker and fail closed when broker is idle"
        )
        try requireSelfTest(
            lostReply.recover(owner, connectionID: lostReplyConnectionID).state == "released"
                && lostReplyBroker.releaseCalls == 1,
            "ambiguous hold must be recoverable by exact tuple release"
        )

        let held = coordinator.begin(owner, connectionID: connectionID)
        try requireSelfTest(held.matches(owner.reference, transition: 2) && held.state == "held",
                            "begin must persist HoldPending, then obtain the exact broker hold")
        try requireSelfTest(store.persisted.first?.state == .holdPending,
                            "HoldPending must be durable before the broker call")
        try requireSelfTest(broker.holdCalls == 1 && broker.heldReference != nil,
                            "exact broker hold must be called once")

        let applied = coordinator.apply(owner.reference, connectionID: connectionID)
        try requireSelfTest(applied.state == "applied" && applied.transition == 3,
                            "route apply must follow the held state")
        try requireSelfTest(Set(executor.added) == Set(owner.privateCIDRs),
                            "all private routes must be applied by the injected executor")

        let released = coordinator.rollback(owner.reference, connectionID: connectionID)
        try requireSelfTest(released.state == "released" && released.transition == 5,
                            "rollback must prove absence before release and reach Released")
        try requireSelfTest(executor.added.isEmpty && broker.heldReference == nil,
                            "route rollback and exact broker release must both complete")
        try requireSelfTest(store.current == nil && broker.releaseCalls == 1,
                            "released journal must be removed only after broker release")
        try requireSelfTest(
            store.persisted.filter { $0.pendingCIDR != nil }.count >= owner.privateCIDRs.count * 2,
            "route deletion must persist a pending marker before each mutation"
        )
        try requireSelfTest(coordinator.rollback(owner.reference, connectionID: connectionID).state == "idle",
                            "duplicate rollback must be idempotent after release")

        let persistedStates = store.persisted.map(\.state)
        try requireSelfTest(
            persistedStates.firstIndex(of: .holdPending) != nil
                && persistedStates.firstIndex(of: .held) != nil
                && persistedStates.firstIndex(of: .applied) != nil
                && persistedStates.firstIndex(of: .retirementPending) != nil
                && persistedStates.firstIndex(of: .released) != nil,
            "journal history must include every interlock state"
        )

        // A release transport failure keeps the hold and enters recovery-only;
        // retrying the exact owner then releases without replaying route adds.
        let retryExecutor = InjectedRouteExecutor()
        let retryBroker = InjectedRouteBrokerV3()
        let retryStore = InjectedRouteJournalV3Store()
        let retry = RouteHelperV3Coordinator(executor: retryExecutor, broker: retryBroker, store: retryStore)
        let retryConnectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000004")!
        try requireSelfTest(retry.register(connectionID: retryConnectionID), "retry connection must register")
        try requireSelfTest(retry.begin(owner, connectionID: retryConnectionID).state == "held",
                            "retry begin must hold the exact broker lease")
        try requireSelfTest(retry.apply(owner.reference, connectionID: retryConnectionID).state == "applied",
                            "retry apply must reach applied")
        retryBroker.failRelease = true
        let failedRelease = retry.rollback(owner.reference, connectionID: retryConnectionID)
        try requireSelfTest(failedRelease.errorCode == "release_failed" && failedRelease.state == "retirement_pending",
                            "release failure must retain RetirementPending and the broker hold")
        try requireSelfTest(retryBroker.heldReference != nil && retryExecutor.added.isEmpty,
                            "release failure must not restore routes or drop the hold")
        try requireSelfTest(retry.status(owner.reference, connectionID: retryConnectionID).state == "retirement_pending",
                            "release failure must remain recovery-only")
        retryBroker.failRelease = false
        let recovered = retry.recover(owner, connectionID: retryConnectionID)
        try requireSelfTest(recovered.state == "released" && retryBroker.heldReference == nil,
                            "same-owner recovery must retry only the exact broker release")
        try requireSelfTest(retryExecutor.addCalls == owner.privateCIDRs.count,
                            "recovery must not replay route additions")

        // A lost post-release journal removal is also retry-safe: the broker's
        // exact tombstone accepts the same release, while a new tuple cannot.
        let tombstoneExecutor = InjectedRouteExecutor()
        let tombstoneBroker = InjectedRouteBrokerV3()
        let tombstoneStore = InjectedRouteJournalV3Store()
        let tombstone = RouteHelperV3Coordinator(
            executor: tombstoneExecutor, broker: tombstoneBroker, store: tombstoneStore
        )
        let tombstoneConnectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000006")!
        try requireSelfTest(tombstone.register(connectionID: tombstoneConnectionID), "tombstone connection must register")
        try requireSelfTest(tombstone.begin(owner, connectionID: tombstoneConnectionID).state == "held",
                            "tombstone begin must hold")
        try requireSelfTest(tombstone.apply(owner.reference, connectionID: tombstoneConnectionID).state == "applied",
                            "tombstone apply must complete")
        tombstoneStore.failRemove = true
        let lostRemoval = tombstone.rollback(owner.reference, connectionID: tombstoneConnectionID)
        try requireSelfTest(lostRemoval.errorCode == "journal_write_failed" && tombstoneBroker.heldReference == nil,
                            "lost journal removal must retain recovery state after exact broker release")
        tombstoneStore.failRemove = false
        let tombstoneRecovered = tombstone.recover(owner, connectionID: tombstoneConnectionID)
        try requireSelfTest(tombstoneRecovered.state == "released" && tombstoneBroker.releaseCalls == 1,
                            "released journal recovery must only unlink the exact tombstone")

        // Startup must not treat a released tombstone whose unlink failed as
        // clean: the durable record remains the recovery authority.
        let startupFailureExecutor = InjectedRouteExecutor()
        let startupFailureBroker = InjectedRouteBrokerV3()
        let startupFailureStore = InjectedRouteJournalV3Store()
        let startupFailure = RouteHelperV3Coordinator(
            executor: startupFailureExecutor, broker: startupFailureBroker, store: startupFailureStore
        )
        let startupFailureConnectionID = UUID(uuidString: "00000000-0000-4000-8000-00000000000b")!
        try requireSelfTest(startupFailure.register(connectionID: startupFailureConnectionID),
                            "startup-failure connection must register")
        try requireSelfTest(startupFailure.begin(owner, connectionID: startupFailureConnectionID).state == "held",
                            "startup-failure fixture must hold")
        startupFailureStore.failRemove = true
        _ = startupFailure.rollback(owner.reference, connectionID: startupFailureConnectionID)
        try requireSelfTest(startupFailureStore.current?.state == .released,
                            "startup-failure fixture must retain released tombstone")
        let restartedStartup = RouteHelperV3Coordinator(
            executor: startupFailureExecutor, broker: startupFailureBroker, store: startupFailureStore
        )
        let startupReply = restartedStartup.reconcileStartup()
        try requireSelfTest(
            startupReply.state == "released" && startupReply.errorCode == "journal_write_failed",
            "startup must report released tombstone unlink failure"
        )
        let postStartupConnectionID = UUID(uuidString: "00000000-0000-4000-8000-00000000000c")!
        try requireSelfTest(restartedStartup.register(connectionID: postStartupConnectionID),
                            "post-startup recovery connection must register")
        try requireSelfTest(restartedStartup.discover(connectionID: postStartupConnectionID).state == "recovery_only",
                            "failed tombstone cleanup must leave coordinator recovery-only")

        // A nil post-delete inspection is not positive absence. Retain the
        // pending CIDR/journal and require a later exact retry.
        let nilPostflightExecutor = InjectedRouteExecutor()
        let nilPostflightBroker = InjectedRouteBrokerV3()
        let nilPostflightStore = InjectedRouteJournalV3Store()
        let nilPostflight = RouteHelperV3Coordinator(
            executor: nilPostflightExecutor, broker: nilPostflightBroker, store: nilPostflightStore
        )
        let nilPostflightConnectionID = UUID(uuidString: "00000000-0000-4000-8000-00000000000d")!
        try requireSelfTest(nilPostflight.register(connectionID: nilPostflightConnectionID),
                            "nil-postflight connection must register")
        try requireSelfTest(nilPostflight.begin(owner, connectionID: nilPostflightConnectionID).state == "held",
                            "nil-postflight fixture must hold")
        try requireSelfTest(nilPostflight.apply(owner.reference, connectionID: nilPostflightConnectionID).state == "applied",
                            "nil-postflight fixture must apply")
        nilPostflightExecutor.failInspectAt = nilPostflightExecutor.inspectCalls + 3
        let nilPostflightReply = nilPostflight.rollback(owner.reference, connectionID: nilPostflightConnectionID)
        try requireSelfTest(
            nilPostflightReply.errorCode == "rollback_failed"
                && nilPostflightStore.current?.pendingCIDR != nil
                && nilPostflight.discover(connectionID: nilPostflightConnectionID).state == "recovery_only",
            "nil post-delete inspection must retain recovery authority"
        )

        // Connection invalidation must execute rollback before releasing the
        // broker hold, while retaining the hold if route cleanup fails.
        let invalidExecutor = InjectedRouteExecutor()
        let invalidBroker = InjectedRouteBrokerV3()
        let invalidStore = InjectedRouteJournalV3Store()
        let invalid = RouteHelperV3Coordinator(
            executor: invalidExecutor, broker: invalidBroker, store: invalidStore
        )
        let invalidConnectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000005")!
        try requireSelfTest(invalid.register(connectionID: invalidConnectionID), "invalidation connection must register")
        try requireSelfTest(invalid.begin(owner, connectionID: invalidConnectionID).state == "held",
                            "invalidation begin must hold")
        try requireSelfTest(invalid.apply(owner.reference, connectionID: invalidConnectionID).state == "applied",
                            "invalidation apply must complete")
        let invalidated = invalid.invalidate(connectionID: invalidConnectionID)
        try requireSelfTest(invalidated.state == "released" && invalidExecutor.added.isEmpty,
                            "connection invalidation must rollback routes before broker release")
        try requireSelfTest(invalidBroker.releaseCalls == 1 && invalidBroker.heldReference == nil,
                            "invalidation must release the same exact broker tuple")

        print("route_v3_interlock_self_test_ok")
        return true
    } catch {
        fputs("route_v3_interlock_self_test_failed: \(error)\n", stderr)
        return false
    }
}

private func runRouteV3DurableStoreSelfTest() -> Bool {
    let fileManager = FileManager.default
    let root = fileManager.temporaryDirectory.appendingPathComponent(
        "kyclash-route-v3-store-\(UUID().uuidString)", isDirectory: true
    )
    do {
        try fileManager.createDirectory(at: root, withIntermediateDirectories: false)
        try fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o700)], ofItemAtPath: root.path)
        defer { try? fileManager.removeItem(at: root) }

        let owner = selfTestOwnerV3(["10.64.0.0/16", "fd00:64::/48"])
        let journalURL = root.appendingPathComponent("route-lease-v3.plist")
        let pending = RouteJournalV3.holdPending(owner: owner)
        let first = DurableRouteJournalV3Store(url: journalURL)
        try requireSelfTest(!first.corrupt && first.current == nil, "new v3 store must start absent")
        try requireSelfTest(first.persist(pending), "v3 store must atomically persist HoldPending")
        guard let info = lstatInfo(journalURL) else {
            throw RouteCoordinatorSelfTestError.failed("v3 journal was not created")
        }
        try requireSelfTest(
            isRegularFile(info) && info.st_nlink == 1 && hasExactPermissions(info, journalFilePermissions),
            "v3 journal must be a private regular 0600 file"
        )
        let restarted = DurableRouteJournalV3Store(url: journalURL)
        try requireSelfTest(restarted.current == pending && !restarted.corrupt,
                            "v3 store must recover the exact journal after restart")

        let replacement = try pending.transitioned(to: .held, reference: owner.reference)
        try PropertyListEncoder().encode(replacement).write(to: journalURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: journalURL.path)
        try requireSelfTest(!restarted.remove(owner.reference),
                            "replaced v3 journal must not be removed under stale memory")
        try requireSelfTest(removeJournalFile(journalURL), "test replacement journal cleanup must succeed")

        // Run the full lifecycle against the durable store while keeping route
        // and broker effects injected and unprivileged.
        let lifecycleURL = root.appendingPathComponent("lifecycle.plist")
        let lifecycleStore = DurableRouteJournalV3Store(url: lifecycleURL)
        let lifecycleBroker = InjectedRouteBrokerV3()
        let lifecycleExecutor = InjectedRouteExecutor()
        let lifecycle = RouteHelperV3Coordinator(
            executor: lifecycleExecutor, broker: lifecycleBroker, store: lifecycleStore
        )
        let connectionID = UUID(uuidString: "00000000-0000-4000-8000-000000000009")!
        try requireSelfTest(lifecycle.register(connectionID: connectionID), "durable lifecycle connection must register")
        try requireSelfTest(lifecycle.begin(owner, connectionID: connectionID).state == "held",
                            "durable lifecycle begin must hold")
        try requireSelfTest(lifecycle.apply(owner.reference, connectionID: connectionID).state == "applied",
                            "durable lifecycle apply must complete")
        try requireSelfTest(lifecycle.rollback(owner.reference, connectionID: connectionID).state == "released",
                            "durable lifecycle rollback must release")
        try requireSelfTest(!fileManager.fileExists(atPath: lifecycleURL.path),
                            "durable lifecycle must remove the journal after release")

        let corruptURL = root.appendingPathComponent("corrupt.plist")
        try Data("not-a-plist".utf8).write(to: corruptURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: corruptURL.path)
        let corrupt = DurableRouteJournalV3Store(url: corruptURL)
        try requireSelfTest(corrupt.corrupt && corrupt.current == nil,
                            "malformed v3 journal must fail closed")

        let symlinkTarget = root.appendingPathComponent("symlink-target")
        let symlinkURL = root.appendingPathComponent("symlink.plist")
        try Data("target".utf8).write(to: symlinkTarget, options: .atomic)
        try fileManager.createSymbolicLink(at: symlinkURL, withDestinationURL: symlinkTarget)
        let symlinkStore = DurableRouteJournalV3Store(url: symlinkURL)
        try requireSelfTest(symlinkStore.corrupt && !symlinkStore.persist(pending),
                            "symlink v3 journal must fail closed for read and write")

        print("route_v3_durable_store_self_test_ok")
        return true
    } catch {
        fputs("route_v3_durable_store_self_test_failed: \(error)\n", stderr)
        try? fileManager.removeItem(at: root)
        return false
    }
}

private func requireDictionary(_ value: Any?) throws -> [String: Any] {
    guard let dictionary = value as? [String: Any] else {
        throw RouteCoordinatorSelfTestError.failed("journal owner was not a dictionary")
    }
    return dictionary
}

private func selfTestCoordinator(
    executor: RouteExecuting,
    journalURL: URL,
    removeJournal: @escaping (URL) -> Bool = removeJournalFile
) -> RouteCoordinator {
    let coordinator = RouteCoordinator(
        executor: executor,
        journalURL: journalURL,
        removeJournal: removeJournal
    )
    precondition(
        coordinator.register(connectionID: coordinatorSelfTestConnectionID),
        "self-test connection registration must be unique"
    )
    return coordinator
}

private func runRouteCoordinatorSelfTest() -> Bool {
    do {
        let auditIdentity = ClientAuditIdentity.validated(
            effectiveUserID: 501,
            processID: 42,
            auditSessionID: 7
        )
        try requireSelfTest(
            auditIdentity == ClientAuditIdentity(processID: 42, auditSessionID: 7),
            "valid non-root audit identity must be retained"
        )
        try requireSelfTest(
            ClientAuditIdentity.validated(effectiveUserID: 0, processID: 42, auditSessionID: 7) == nil,
            "root client must be rejected"
        )
        try requireSelfTest(
            ClientAuditIdentity.validated(effectiveUserID: 501, processID: 1, auditSessionID: 7) == nil,
            "launchd/kernel PID must be rejected"
        )
        try requireSelfTest(
            ClientAuditIdentity.validated(
                effectiveUserID: 501,
                processID: 42,
                auditSessionID: AU_DEFAUDITSID
            ) == nil,
            "default audit session must be rejected"
        )
        try requireSelfTest(
            ClientAuditIdentity.validated(
                effectiveUserID: 501,
                processID: 42,
                auditSessionID: AU_ASSIGN_ASID
            ) == nil,
            "unassigned audit session must be rejected"
        )
        try requireSelfTest(validUtunInterface("utun0"), "utun0 must be canonical")
        try requireSelfTest(validUtunInterface("utun42"), "utun42 must be canonical")
        try requireSelfTest(!validUtunInterface("utun007"), "leading-zero utun names must be refused")

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("kyclash-route-helper-self-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                 attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }

        let cidrs = ["10.64.0.0/16", "fd00:64::/48"]
        let owner = selfTestOwner(cidrs)
        let archivedOwner = try NSKeyedArchiver.archivedData(
            withRootObject: owner,
            requiringSecureCoding: true
        )
        let decodedOwner = try NSKeyedUnarchiver.unarchivedObject(
            ofClass: LeaseOwner.self,
            from: archivedOwner
        )
        try requireSelfTest(
            decodedOwner?.hasIPv4 == true && decodedOwner?.hasIPv6 == true
                && decodedOwner?.isValid() == true,
            "NSSecureCoding must preserve dual-stack family facts"
        )

        // Default-route takeover is never a valid KyClash private route. Keep
        // the refusal explicit in the in-memory helper gate so a future CIDR
        // parser change cannot silently widen the mutation scope.
        let defaultRouteExecutor = InjectedRouteExecutor()
        try requireSelfTest(defaultRouteExecutor.inspect(
            cidrs: ["0.0.0.0/0"], interfaceName: "utun42", trustedMihomoInterfaces: []
        ) == nil,
                            "IPv4 default route must be refused")
        try requireSelfTest(defaultRouteExecutor.inspect(
            cidrs: ["::/0"], interfaceName: "utun42", trustedMihomoInterfaces: []
        ) == nil,
                            "IPv6 default route must be refused")
        for invalidCIDR in [
            "1.2.3.4/0", "224.0.0.0/4", "ff00::/8", "10.0.0.1/24",
            "10.0.0.0/nope", "10.0.0.0", "10.0.0.0/+24", "fd00::%utun4/48",
            "10/8", "10.0/16", "10.0.0/24", "10.0.0.0/016", "FD00::/48",
            "fd00:0::/48"
        ] {
            try requireSelfTest(InjectedRouteExecutor().inspect(
                cidrs: [invalidCIDR], interfaceName: "utun42", trustedMihomoInterfaces: []
            ) == nil,
                                "invalid/non-canonical CIDR must be refused: \(invalidCIDR)")
        }
        let overlappingOwner = selfTestOwner(["10.64.0.0/16", "10.64.1.0/24"])
        try requireSelfTest(!overlappingOwner.isValid(), "overlapping desired CIDRs must be refused")

        // Normal IPv4+IPv6 cycle, duplicate messages, replay mismatch, and
        // explicit connection invalidation all remain idempotent.
        let normalExecutor = InjectedRouteExecutor()
        let normal = selfTestCoordinator(executor: normalExecutor, journalURL: root.appendingPathComponent("normal.plist"))
        try requireSelfTest(normal.discover().state == "idle", "normal discover must start idle")
        try requireSelfTest(normal.begin(owner).state == "prepared", "normal begin must prepare")
        try requireSelfTest(normal.apply(owner.reference).state == "applied", "normal apply must apply both families")
        try requireSelfTest(normal.apply(owner.reference).state == "applied", "duplicate apply must be idempotent")
        try requireSelfTest(normal.heartbeat(owner.reference).state == "applied", "heartbeat must refresh an active lease")
        let replay = LeaseReference(version: protocolVersion, leaseID: "lease.replayed.v1", operationID: owner.reference.operationID)
        try requireSelfTest(normal.status(replay).errorCode == "ownership_mismatch", "replayed lease must be rejected")
        normal.expireLeaseForSelfTest()
        try requireSelfTest(normal.discover().state == "idle" && normalExecutor.added.isEmpty,
                            "lease expiry must remove owned routes")

        // A second cycle exercises the XPC invalidation cleanup boundary
        // independently from heartbeat expiry.
        try requireSelfTest(normal.begin(owner).state == "prepared", "invalidation cycle must prepare")
        try requireSelfTest(normal.apply(owner.reference).state == "applied", "invalidation cycle must apply")
        try requireSelfTest(normal.unregister().state == "idle" && normalExecutor.added.isEmpty,
                            "connection unregister must remove owned routes")
        try requireSelfTest(normal.discover().errorCode == "ownership_mismatch",
                            "unregistered connection must not discover")

        // Registration is the helper-side A/B barrier. B cannot certify idle
        // while A is still accepted, including before A's already queued begin
        // reaches the coordinator. Once A unregisters, its exact owned routes
        // are rolled back under the same lock and only the still-live B can
        // certify authoritative idle.
        let connectionExecutor = InjectedRouteExecutor()
        let connectionCoordinator = RouteCoordinator(
            executor: connectionExecutor,
            journalURL: root.appendingPathComponent("connection-owner.plist")
        )
        let connectionA = UUID()
        let connectionB = UUID()
        let unknownConnection = UUID()
        try requireSelfTest(
            connectionCoordinator.begin(owner, connectionID: connectionA).errorCode == "ownership_mismatch",
            "unregistered A must not begin"
        )
        try requireSelfTest(
            connectionCoordinator.register(connectionID: connectionA)
                && connectionCoordinator.register(connectionID: connectionB),
            "A and B registrations must be accepted"
        )
        try requireSelfTest(
            !connectionCoordinator.register(connectionID: connectionA),
            "duplicate registration must be rejected"
        )
        try requireSelfTest(
            connectionCoordinator.discover(connectionID: connectionB).errorCode == "not_ready",
            "B must not certify idle before A's late begin"
        )
        try requireSelfTest(
            connectionCoordinator.begin(owner, connectionID: connectionA).state == "prepared",
            "registered A's late begin must still be serialized"
        )
        try requireSelfTest(
            connectionCoordinator.discover(connectionID: connectionB).errorCode == "not_ready",
            "B must remain not_ready while A owns a prepared lease"
        )
        try requireSelfTest(
            connectionCoordinator.apply(owner.reference, connectionID: connectionB).errorCode == "ownership_mismatch",
            "second XPC connection must not apply another lease"
        )
        try requireSelfTest(
            connectionCoordinator.recover(owner, connectionID: connectionB).errorCode == "ownership_mismatch",
            "second XPC connection must not recover a live lease"
        )
        try requireSelfTest(
            connectionCoordinator.heartbeat(owner.reference, connectionID: connectionB).errorCode == "ownership_mismatch",
            "second XPC connection must not heartbeat another lease"
        )
        try requireSelfTest(
            connectionCoordinator.status(owner.reference, connectionID: connectionB).errorCode == "ownership_mismatch",
            "second XPC connection must not inspect another lease"
        )
        try requireSelfTest(
            connectionCoordinator.unregister(connectionID: unknownConnection).errorCode == "ownership_mismatch"
                && connectionCoordinator.discover(connectionID: connectionB).errorCode == "not_ready",
            "unknown unregister must not change the registered connection barrier"
        )
        try requireSelfTest(
            connectionCoordinator.apply(owner.reference, connectionID: connectionA).state == "applied",
            "owning XPC connection must apply"
        )
        try requireSelfTest(
            connectionCoordinator.rollback(owner.reference, connectionID: connectionB).errorCode == "ownership_mismatch",
            "second XPC connection must not roll back another lease"
        )
        try requireSelfTest(!connectionExecutor.added.isEmpty, "foreign rollback must not delete owned routes")
        try requireSelfTest(
            connectionCoordinator.unregister(connectionID: connectionA).state == "idle"
                && connectionExecutor.added.isEmpty,
            "owning A unregister must roll back and release its lease"
        )
        try requireSelfTest(
            connectionCoordinator.discover(connectionID: connectionA).errorCode == "ownership_mismatch"
                && connectionCoordinator.begin(owner, connectionID: connectionA).errorCode == "ownership_mismatch"
                && connectionCoordinator.apply(owner.reference, connectionID: connectionA).errorCode == "ownership_mismatch"
                && connectionCoordinator.rollback(owner.reference, connectionID: connectionA).errorCode == "ownership_mismatch"
                && connectionCoordinator.recover(owner, connectionID: connectionA).errorCode == "ownership_mismatch"
                && connectionCoordinator.heartbeat(owner.reference, connectionID: connectionA).errorCode == "ownership_mismatch"
                && connectionCoordinator.status(owner.reference, connectionID: connectionA).errorCode == "ownership_mismatch"
                && connectionCoordinator.unregister(connectionID: connectionA).errorCode == "ownership_mismatch",
            "unregistered A must be rejected by every coordinator operation"
        )
        try requireSelfTest(
            connectionCoordinator.discover(connectionID: connectionB).state == "idle",
            "sole registered B must certify authoritative idle"
        )

        // A failed unregister rollback removes the dead registration but
        // retains both the durable journal and active-owner tombstone. The
        // fresh sole B sees recovery_required, never idle, and stale A cannot
        // adopt or mutate the frozen transaction.
        let unregisterFailureExecutor = InjectedRouteExecutor()
        let unregisterFailurePath = root.appendingPathComponent("unregister-rollback-failure.plist")
        let unregisterFailure = RouteCoordinator(
            executor: unregisterFailureExecutor,
            journalURL: unregisterFailurePath
        )
        let failureA = UUID()
        let failureB = UUID()
        try requireSelfTest(
            unregisterFailure.register(connectionID: failureA)
                && unregisterFailure.register(connectionID: failureB),
            "rollback-failure A/B registrations must succeed"
        )
        try requireSelfTest(
            unregisterFailure.begin(owner, connectionID: failureA).state == "prepared"
                && unregisterFailure.apply(owner.reference, connectionID: failureA).state == "applied",
            "rollback-failure fixture must own applied routes"
        )
        unregisterFailureExecutor.failDeleteAt = unregisterFailureExecutor.deleteCalls
        try requireSelfTest(
            unregisterFailure.unregister(connectionID: failureA).errorCode == "rollback_failed",
            "failed A unregister must surface rollback failure"
        )
        try requireSelfTest(
            unregisterFailure.discover(connectionID: failureB).errorCode == "recovery_required"
                && unregisterFailure.recover(owner, connectionID: failureB).errorCode == "ownership_mismatch"
                && !unregisterFailureExecutor.added.isEmpty
                && FileManager.default.fileExists(atPath: unregisterFailurePath.path),
            "sole B must see recovery_required and cannot adopt failed A ownership"
        )
        try requireSelfTest(
            unregisterFailure.discover(connectionID: failureA).errorCode == "ownership_mismatch"
                && unregisterFailure.recover(owner, connectionID: failureA).errorCode == "ownership_mismatch"
                && unregisterFailure.rollback(owner.reference, connectionID: failureA).errorCode == "ownership_mismatch",
            "failed unregister must still reject stale A"
        )
        unregisterFailureExecutor.failDeleteAt = nil
        unregisterFailure.expireLeaseForSelfTest()
        try requireSelfTest(
            unregisterFailure.discover(connectionID: failureB).state == "idle"
                && unregisterFailureExecutor.added.isEmpty,
            "successful frozen-owner retry must restore authoritative B idle"
        )

        // A helper process generation that starts with a durable v2 journal
        // must synchronously try rollback before accepting requests. If that
        // recovery fails, the fresh connection can only discover the frozen
        // recovery state; even an exact owner payload cannot cross the XPC
        // generation boundary and adopt it.
        let startupFailurePath = root.appendingPathComponent("startup-rollback-failure.plist")
        let startupFailureExecutor = InjectedRouteExecutor()
        do {
            let first = selfTestCoordinator(
                executor: startupFailureExecutor,
                journalURL: startupFailurePath
            )
            try requireSelfTest(first.begin(owner).state == "prepared",
                                "startup-failure fixture must prepare")
            try requireSelfTest(first.apply(owner.reference).state == "applied",
                                "startup-failure fixture must apply")
        }
        startupFailureExecutor.failDeleteAt = startupFailureExecutor.deleteCalls
        let failedStartup = RouteCoordinator(
            executor: startupFailureExecutor,
            journalURL: startupFailurePath
        )
        let startupFreshConnection = UUID()
        try requireSelfTest(
            failedStartup.register(connectionID: startupFreshConnection),
            "fresh startup connection registration must succeed"
        )
        try requireSelfTest(
            failedStartup.discover(connectionID: startupFreshConnection).errorCode == "recovery_required"
                && failedStartup.recover(owner, connectionID: startupFreshConnection).errorCode == "ownership_mismatch"
                && !startupFailureExecutor.added.isEmpty
                && FileManager.default.fileExists(atPath: startupFailurePath.path),
            "failed startup rollback must retain routes and journal without cross-generation adoption"
        )
        startupFailureExecutor.failDeleteAt = nil
        failedStartup.expireLeaseForSelfTest()
        try requireSelfTest(
            failedStartup.discover(connectionID: startupFreshConnection).state == "idle"
                && startupFailureExecutor.added.isEmpty
                && !FileManager.default.fileExists(atPath: startupFailurePath.path),
            "later internal recovery must restore authoritative fresh-connection idle"
        )

        // A prepared lease has no applied or pending CIDR yet.  Rollback must
        // still remove its journal, and a duplicate rollback must remain
        // idempotent instead of failing on an empty inspection set.
        let preparedExecutor = InjectedRouteExecutor()
        let preparedRollback = selfTestCoordinator(
            executor: preparedExecutor,
            journalURL: root.appendingPathComponent("prepared-rollback.plist")
        )
        try requireSelfTest(preparedRollback.begin(owner).state == "prepared",
                            "empty rollback begin must prepare")
        try requireSelfTest(preparedRollback.rollback(owner.reference).state == "idle",
                            "empty rollback must clear a prepared journal")
        try requireSelfTest(preparedRollback.discover().state == "idle",
                            "empty rollback must leave idle state")
        try requireSelfTest(preparedRollback.rollback(owner.reference).state == "idle",
                            "empty rollback retry must be idempotent")

        // A journal path supplied as a symlink is never trusted, even when it
        // points at an otherwise readable file.  The target must remain
        // untouched and the helper must fail closed before any route work.
        let symlinkTarget = root.appendingPathComponent("journal-target.plist")
        let symlinkPath = root.appendingPathComponent("journal-symlink.plist")
        try Data("not-a-journal".utf8).write(to: symlinkTarget, options: [.atomic])
        try FileManager.default.createSymbolicLink(at: symlinkPath, withDestinationURL: symlinkTarget)
        let symlinkCoordinator = selfTestCoordinator(
            executor: InjectedRouteExecutor(),
            journalURL: symlinkPath
        )
        try requireSelfTest(symlinkCoordinator.discover().errorCode == "journal_corrupt",
                            "symlinked journal must fail closed")
        try requireSelfTest(symlinkCoordinator.begin(owner).errorCode == "invalid_owner",
                            "symlinked journal must reject begin")
        try requireSelfTest(FileManager.default.fileExists(atPath: symlinkTarget.path),
                            "symlink target must remain present")

        // A pre-existing exact route is a conflict and must be rejected before
        // a journal is written or any mutation is attempted.
        let conflictExecutor = InjectedRouteExecutor()
        conflictExecutor.existing = [cidrs[0]]
        let conflict = selfTestCoordinator(executor: conflictExecutor, journalURL: root.appendingPathComponent("conflict.plist"))
        try requireSelfTest(conflict.begin(owner).errorCode == "route_conflict", "exact pre-existing route must conflict")
        try requireSelfTest(conflictExecutor.added.isEmpty, "conflict must not mutate routes")

        // Only a frozen, explicitly trusted Mihomo interface may provide a
        // less-specific covering route.  Exact and more-specific routes still
        // conflict even when the interface is trusted, and an unknown VPN's
        // covering route remains a conflict.
        let mihomoOwner = selfTestOwner(["10.64.0.0/16"], activeMihomoTunInterfaces: ["utun123"])
        let trustedBroadExecutor = InjectedRouteExecutor()
        trustedBroadExecutor.existing.insert("0.0.0.0/1")
        trustedBroadExecutor.existingRouteInterfaces["0.0.0.0/1"] = "utun123"
        let trustedBroad = selfTestCoordinator(
            executor: trustedBroadExecutor,
            journalURL: root.appendingPathComponent("trusted-broad.plist")
        )
        try requireSelfTest(trustedBroad.begin(mihomoOwner).state == "prepared",
                            "trusted Mihomo covering route must be allowed")
        try requireSelfTest(trustedBroad.apply(mihomoOwner.reference).state == "applied",
                            "trusted Mihomo covering route apply must succeed")
        try requireSelfTest(trustedBroad.rollback(mihomoOwner.reference).state == "idle",
                            "trusted Mihomo covering route rollback must succeed")
        try requireSelfTest(trustedBroadExecutor.existing.contains("0.0.0.0/1"),
                            "trusted Mihomo covering route must never be deleted")

        let unknownBroadExecutor = InjectedRouteExecutor()
        unknownBroadExecutor.existing.insert("0.0.0.0/1")
        unknownBroadExecutor.existingRouteInterfaces["0.0.0.0/1"] = "en0"
        let unknownBroad = selfTestCoordinator(
            executor: unknownBroadExecutor,
            journalURL: root.appendingPathComponent("unknown-broad.plist")
        )
        try requireSelfTest(unknownBroad.begin(mihomoOwner).errorCode == "route_conflict",
                            "unknown covering route must conflict")

        let exactTrustedExecutor = InjectedRouteExecutor()
        exactTrustedExecutor.existing.insert("10.64.0.0/16")
        exactTrustedExecutor.existingRouteInterfaces["10.64.0.0/16"] = "utun123"
        let exactTrusted = selfTestCoordinator(
            executor: exactTrustedExecutor,
            journalURL: root.appendingPathComponent("exact-trusted.plist")
        )
        try requireSelfTest(exactTrusted.begin(mihomoOwner).errorCode == "route_conflict",
                            "trusted exact route must conflict")

        let moreSpecificTrustedExecutor = InjectedRouteExecutor()
        moreSpecificTrustedExecutor.existing.insert("10.64.1.0/24")
        moreSpecificTrustedExecutor.existingRouteInterfaces["10.64.1.0/24"] = "utun123"
        let moreSpecificTrusted = selfTestCoordinator(
            executor: moreSpecificTrustedExecutor,
            journalURL: root.appendingPathComponent("more-specific-trusted.plist")
        )
        try requireSelfTest(moreSpecificTrusted.begin(mihomoOwner).errorCode == "route_conflict",
                            "trusted more-specific route must conflict")

        // Inject failure before each add.  The coordinator must journal the
        // pending route and roll back every route it already added.
        for failAt in 0...1 {
            let executor = InjectedRouteExecutor()
            executor.failAddAt = failAt
            let coordinator = selfTestCoordinator(executor: executor,
                                                    journalURL: root.appendingPathComponent("add-failure-\(failAt).plist"))
            try requireSelfTest(coordinator.begin(owner).state == "prepared", "faulted begin must prepare")
            try requireSelfTest(coordinator.apply(owner.reference).errorCode == "route_apply_failed",
                                "add failure \(failAt) must fail closed")
            try requireSelfTest(executor.added.isEmpty, "add failure \(failAt) leaked a route")
        }

        // A route command may report failure after the kernel has already
        // installed the route.  The durable pending CIDR must remain until
        // exact-state inspection proves the owned route was removed.
        let ambiguousExecutor = InjectedRouteExecutor()
        ambiguousExecutor.failAddAfterMutationAt = 1
        let ambiguous = selfTestCoordinator(executor: ambiguousExecutor,
                                             journalURL: root.appendingPathComponent("ambiguous-add.plist"))
        try requireSelfTest(ambiguous.begin(owner).state == "prepared", "ambiguous begin must prepare")
        try requireSelfTest(ambiguous.apply(owner.reference).errorCode == "route_apply_failed",
                            "ambiguous add must fail closed")
        try requireSelfTest(ambiguousExecutor.added.isEmpty, "ambiguous add leaked a route")

        // Force rollback itself to fail once, verify the stronger error is
        // surfaced, then retry after the injected fault is consumed.
        let rollbackExecutor = InjectedRouteExecutor()
        let rollback = selfTestCoordinator(executor: rollbackExecutor, journalURL: root.appendingPathComponent("rollback-failure.plist"))
        try requireSelfTest(rollback.begin(owner).state == "prepared", "rollback fault begin must prepare")
        try requireSelfTest(rollback.apply(owner.reference).state == "applied", "rollback fault apply must apply")
        rollbackExecutor.failDeleteAt = rollbackExecutor.deleteCalls
        try requireSelfTest(rollback.rollback(owner.reference).errorCode == "rollback_failed",
                            "rollback failure must be surfaced")
        rollbackExecutor.failDeleteAt = nil
        try requireSelfTest(rollback.rollback(owner.reference).state == "idle", "rollback retry must recover")
        try requireSelfTest(rollbackExecutor.added.isEmpty, "rollback retry must remove all routes")

        // A durable write failure before the first delete must stop the
        // rollback with its pending marker intact; it must not continue to a
        // later CIDR and overwrite the unresolved state.  Removing the test
        // symlink permits a deterministic retry and proves recovery remains
        // possible once persistence is available again.
        let persistFailurePath = root.appendingPathComponent("rollback-persist-failure.plist")
        let persistFailureTarget = root.appendingPathComponent("rollback-persist-target.plist")
        let persistFailureExecutor = InjectedRouteExecutor()
        let persistFailure = selfTestCoordinator(
            executor: persistFailureExecutor,
            journalURL: persistFailurePath
        )
        try requireSelfTest(persistFailure.begin(owner).state == "prepared",
                            "persist-failure begin must prepare")
        try requireSelfTest(persistFailure.apply(owner.reference).state == "applied",
                            "persist-failure apply must apply")
        try Data("sentinel".utf8).write(to: persistFailureTarget, options: [.atomic])
        try FileManager.default.removeItem(at: persistFailurePath)
        try FileManager.default.createSymbolicLink(at: persistFailurePath, withDestinationURL: persistFailureTarget)
        try requireSelfTest(persistFailure.rollback(owner.reference).errorCode == "rollback_failed",
                            "rollback persistence failure must fail closed")
        try requireSelfTest(persistFailureExecutor.added.count == cidrs.count,
                            "rollback persistence failure must not skip/overwrite pending state")
        try FileManager.default.removeItem(at: persistFailurePath)
        try requireSelfTest(persistFailure.rollback(owner.reference).state == "idle",
                            "rollback persistence failure must recover after retry")
        try requireSelfTest(persistFailureExecutor.added.isEmpty,
                            "rollback persistence retry must remove all routes")

        // A foreign route appearing after apply must not prevent removal of
        // the exact owned route or cause the foreign route to be deleted.
        let foreignExecutor = InjectedRouteExecutor()
        let foreign = selfTestCoordinator(executor: foreignExecutor, journalURL: root.appendingPathComponent("foreign-after-apply.plist"))
        try requireSelfTest(foreign.begin(owner).state == "prepared", "foreign begin must prepare")
        try requireSelfTest(foreign.apply(owner.reference).state == "applied", "foreign apply must apply")
        foreignExecutor.existing.insert(cidrs[0])
        try requireSelfTest(foreign.rollback(owner.reference).state == "idle", "foreign rollback must remove owned state")
        try requireSelfTest(foreignExecutor.added.isEmpty && foreignExecutor.existing == [cidrs[0]],
                            "foreign rollback must preserve the foreign route")

        let foreignOnlyExecutor = InjectedRouteExecutor()
        let foreignOnly = selfTestCoordinator(
            executor: foreignOnlyExecutor,
            journalURL: root.appendingPathComponent("foreign-only.plist")
        )
        try requireSelfTest(foreignOnly.begin(owner).state == "prepared", "foreign-only begin must prepare")
        try requireSelfTest(foreignOnly.apply(owner.reference).state == "applied", "foreign-only apply must apply")
        foreignOnlyExecutor.added.removeAll()
        foreignOnlyExecutor.existing.insert(cidrs[0])
        try requireSelfTest(foreignOnly.rollback(owner.reference).errorCode == "rollback_failed",
                            "foreign-only rollback must remain recovery-required")

        // Journal unlink failure keeps recovery required; a later retry can
        // complete and the same reference is idempotent after success.
        var allowJournalRemoval = false
        let unlink = selfTestCoordinator(
            executor: InjectedRouteExecutor(),
            journalURL: root.appendingPathComponent("unlink-failure.plist"),
            removeJournal: { _ in allowJournalRemoval }
        )
        try requireSelfTest(unlink.begin(owner).state == "prepared", "unlink begin must prepare")
        try requireSelfTest(unlink.apply(owner.reference).state == "applied", "unlink apply must apply")
        try requireSelfTest(unlink.rollback(owner.reference).errorCode == "rollback_failed",
                            "unlink failure must remain recovery-required")
        try requireSelfTest(unlink.discover().errorCode == "recovery_required",
                            "unlink failure must not enter idle")
        allowJournalRemoval = true
        try requireSelfTest(unlink.rollback(owner.reference).state == "idle", "unlink retry must recover")
        try requireSelfTest(unlink.rollback(owner.reference).state == "idle", "duplicate rollback must be idempotent")

        // Simulate helper restart with a durable applied journal and in-memory
        // routes.  A new coordinator must reconcile them before accepting a
        // discover request.
        let restartPath = root.appendingPathComponent("restart.plist")
        let restartExecutor = InjectedRouteExecutor()
        do {
            let first = selfTestCoordinator(executor: restartExecutor, journalURL: restartPath)
            try requireSelfTest(first.begin(owner).state == "prepared", "restart begin must prepare")
            try requireSelfTest(first.apply(owner.reference).state == "applied", "restart apply must apply")
        }
        try requireSelfTest(!restartExecutor.added.isEmpty, "restart fixture must leave durable routes")
        let restarted = selfTestCoordinator(executor: restartExecutor, journalURL: restartPath)
        try requireSelfTest(restarted.discover().state == "idle" && restartExecutor.added.isEmpty,
                            "helper restart must recover routes before discover")

        // A v1 journal is accepted only for rollback migration.  It must be
        // consumed without creating a v2 lease and must never authorize a new
        // apply operation.
        let legacyPath = root.appendingPathComponent("legacy-v1.plist")
        let legacyExecutor = InjectedRouteExecutor()
        legacyExecutor.added = cidrs
        let legacyJournal = LegacyRouteJournal(
            version: legacyProtocolVersion,
            owner: LegacyJournalOwner(JournalOwner(owner)),
            pendingCIDR: cidrs[0],
            appliedCIDRs: cidrs
        )
        try PropertyListEncoder().encode(legacyJournal).write(to: legacyPath, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: journalFilePermissions], ofItemAtPath: legacyPath.path)
        let migrated = selfTestCoordinator(executor: legacyExecutor, journalURL: legacyPath)
        try requireSelfTest(migrated.discover().state == "idle", "legacy journal must rollback during startup")
        try requireSelfTest(legacyExecutor.added.isEmpty, "legacy rollback must remove only exact owned routes")
        try requireSelfTest(!FileManager.default.fileExists(atPath: legacyPath.path), "legacy journal must be removed after rollback")

        let ambiguousLegacyPath = root.appendingPathComponent("legacy-v1-foreign.plist")
        let ambiguousLegacyExecutor = InjectedRouteExecutor()
        ambiguousLegacyExecutor.existing.insert(cidrs[0])
        let ambiguousLegacy = LegacyRouteJournal(
            version: legacyProtocolVersion,
            owner: LegacyJournalOwner(JournalOwner(owner)),
            pendingCIDR: nil,
            appliedCIDRs: [cidrs[0]]
        )
        try PropertyListEncoder().encode(ambiguousLegacy).write(to: ambiguousLegacyPath, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: journalFilePermissions],
            ofItemAtPath: ambiguousLegacyPath.path
        )
        let refusedLegacy = selfTestCoordinator(
            executor: ambiguousLegacyExecutor,
            journalURL: ambiguousLegacyPath
        )
        try requireSelfTest(
            refusedLegacy.discover().errorCode == "recovery_required",
            "ambiguous legacy ownership must remain recovery required"
        )
        try requireSelfTest(
            ambiguousLegacyExecutor.existing == [cidrs[0]] && ambiguousLegacyExecutor.deleteCalls == 0,
            "legacy migration must never delete a foreign route"
        )

        // Corrupt journals fail closed and never attempt route mutation.
        let corruptPath = root.appendingPathComponent("corrupt.plist")
        try Data("not-a-property-list".utf8).write(to: corruptPath, options: [.atomic])
        let corruptExecutor = InjectedRouteExecutor()
        let corrupt = selfTestCoordinator(executor: corruptExecutor, journalURL: corruptPath)
        try requireSelfTest(corrupt.discover().errorCode == "journal_corrupt", "corrupt journal must fail closed")
        try requireSelfTest(corruptExecutor.added.isEmpty, "corrupt journal must not mutate routes")

        let unknownPath = root.appendingPathComponent("unknown-field-corrupt.plist")
        let validJournal = RouteJournal(version: protocolVersion, owner: JournalOwner(owner), pendingCIDR: nil, appliedCIDRs: [])
        let validData = try PropertyListEncoder().encode(validJournal)
        var propertyList = try PropertyListSerialization.propertyList(
            from: validData,
            options: .mutableContainersAndLeaves,
            format: nil
        ) as! [String: Any]
        propertyList["unexpected"] = "reject-me"
        let unknownData = try PropertyListSerialization.data(
            fromPropertyList: propertyList,
            format: .binary,
            options: 0
        )
        try unknownData.write(to: unknownPath, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: journalFilePermissions], ofItemAtPath: unknownPath.path)
        let unknown = selfTestCoordinator(executor: InjectedRouteExecutor(), journalURL: unknownPath)
        try requireSelfTest(unknown.discover().errorCode == "journal_corrupt",
                            "unknown journal fields must fail closed")

        // A syntactically valid plist with an owner/applied mismatch is still
        // corrupt.  It must never reach the route executor, because otherwise
        // a forged applied CIDR could be interpreted as an owned delete.
        let semanticPath = root.appendingPathComponent("semantic-corrupt.plist")
        let semanticJournal = RouteJournal(
            version: protocolVersion,
            owner: JournalOwner(owner),
            pendingCIDR: "10.65.0.0/16",
            appliedCIDRs: ["10.65.0.0/16"]
        )
        try PropertyListEncoder().encode(semanticJournal).write(to: semanticPath, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: journalFilePermissions], ofItemAtPath: semanticPath.path)
        let semanticExecutor = InjectedRouteExecutor()
        let semantic = selfTestCoordinator(executor: semanticExecutor, journalURL: semanticPath)
        try requireSelfTest(semantic.discover().errorCode == "journal_corrupt",
                            "semantic journal corruption must fail closed")
        try requireSelfTest(semanticExecutor.added.isEmpty,
                            "semantic journal corruption must not mutate routes")

        let overlappingPendingPath = root.appendingPathComponent("pending-overlap-corrupt.plist")
        let overlappingPendingJournal = RouteJournal(
            version: protocolVersion,
            owner: JournalOwner(owner),
            pendingCIDR: cidrs[0],
            appliedCIDRs: [cidrs[0]]
        )
        try PropertyListEncoder().encode(overlappingPendingJournal)
            .write(to: overlappingPendingPath, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: journalFilePermissions],
            ofItemAtPath: overlappingPendingPath.path
        )
        let overlappingPending = selfTestCoordinator(
            executor: InjectedRouteExecutor(),
            journalURL: overlappingPendingPath
        )
        try requireSelfTest(overlappingPending.discover().errorCode == "journal_corrupt",
                            "pending/applied overlap must fail closed")

        // Status and recover must inspect live route ownership instead of
        // trusting only the applied-CIDR count in the journal.
        let livePath = root.appendingPathComponent("live-status.plist")
        let liveExecutor = InjectedRouteExecutor()
        let live = selfTestCoordinator(executor: liveExecutor, journalURL: livePath)
        try requireSelfTest(live.begin(owner).state == "prepared", "live status begin must prepare")
        try requireSelfTest(live.status(owner.reference).state == "prepared",
                            "prepared status must inspect absent owned routes")
        try requireSelfTest(live.recover(owner).state == "prepared",
                            "prepared recover must inspect absent owned routes")
        try requireSelfTest(live.apply(owner.reference).state == "applied", "live status apply must apply")
        liveExecutor.existing.insert(cidrs[0])
        try requireSelfTest(live.status(owner.reference).errorCode == "recovery_required",
                            "foreign overlap must invalidate applied status")
        try requireSelfTest(live.recover(owner).errorCode == "recovery_required",
                            "foreign overlap must reject applied recovery")

        print("route_coordinator_self_test_ok")
        return true
    } catch {
        fputs("route_coordinator_self_test_failed: \(error)\n", stderr)
        return false
    }
}

@main
private enum RouteHelperMain {
    static func main() {
        if CommandLine.arguments.contains("--route-readonly-self-test") {
            guard routeLookupSelfTest() else {
                fputs("route_readonly_self_test_failed\n", stderr)
                exit(1)
            }
            let executor = SystemRouteExecutor()
            // Availability is intentionally environment-dependent: an active
            // VPN may own a broad overlap and must make this probe return
            // false.  The deterministic parser/overlap assertions above are
            // the gate; these calls prove the system adapter remains read-only
            // and bounded on the current machine.
            _ = executor.inspect(
                cidrs: ["10.127.0.0/16"], interfaceName: "utun999", trustedMihomoInterfaces: []
            )
            _ = executor.inspect(
                cidrs: ["fd00:127::/48"], interfaceName: "utun999", trustedMihomoInterfaces: []
            )
            print("route_readonly_self_test_ok")
            return
        }
        if CommandLine.arguments.contains("--route-v3-contract-self-test") {
            if !runRouteV3WireJournalSelfTest() { exit(1) }
            return
        }
        if CommandLine.arguments.contains("--route-v3-interlock-self-test") {
            if !runRouteV3InterlockSelfTest() { exit(1) }
            return
        }
        if CommandLine.arguments.contains("--route-v3-durable-store-self-test") {
            if !runRouteV3DurableStoreSelfTest() { exit(1) }
            return
        }
        if CommandLine.arguments.contains("--route-v3-bridge-self-test") {
            if !runRouteV3BridgeSelfTest() { exit(1) }
            return
        }
        if CommandLine.arguments.contains("--route-coordinator-self-test") {
            if !runRouteCoordinatorSelfTest() { exit(1) }
            return
        }
        if CommandLine.arguments.contains("--route-v3-lab-listener") {
            runRouteV3LabListener()
        }
        if CommandLine.arguments.contains("--route-v2-lab-listener") {
            runRouteV2LabListener()
        }
        // Production always exposes the broker-bound v3 listener. Legacy v2
        // code remains compiled for recovery/self-test coverage but is never
        // selected by the signed launchd helper.
        runRouteV3ProductionListener()
    }
}
