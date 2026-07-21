import Foundation

private let protocolVersion: UInt8 = 1
private let appRequirement = "anchor apple generic and identifier \"net.kysion.kyclash\" and certificate leaf[subject.OU] = \"RQUQ8Y3S9H\""

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
        version = UInt8(coder.decodeInteger(forKey: "version"))
        guard let lease = coder.decodeObject(of: NSString.self, forKey: "leaseID") as String?,
              let operation = coder.decodeObject(of: NSString.self, forKey: "operationID") as String?
        else { return nil }
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
    let privateCIDRs: [String]

    init(reference: LeaseReference, sidecarInstanceID: String, interfaceName: String,
         tunnelOperationID: String, mtu: UInt16, profileRevision: UInt64,
         privateCIDRs: [String]) {
        self.reference = reference
        self.sidecarInstanceID = sidecarInstanceID
        self.interfaceName = interfaceName
        self.tunnelOperationID = tunnelOperationID
        self.mtu = mtu
        self.profileRevision = profileRevision
        self.privateCIDRs = privateCIDRs
    }

    required init?(coder: NSCoder) {
        guard let reference = coder.decodeObject(of: LeaseReference.self, forKey: "reference"),
              let instance = coder.decodeObject(of: NSString.self, forKey: "sidecarInstanceID") as String?,
              let interfaceName = coder.decodeObject(of: NSString.self, forKey: "interfaceName") as String?,
              let tunnelOperation = coder.decodeObject(of: NSString.self, forKey: "tunnelOperationID") as String?,
              let cidrs = coder.decodeObject(of: [NSArray.self, NSString.self], forKey: "privateCIDRs") as? [String]
        else { return nil }
        self.reference = reference
        sidecarInstanceID = instance
        self.interfaceName = interfaceName
        tunnelOperationID = tunnelOperation
        mtu = UInt16(coder.decodeInteger(forKey: "mtu"))
        profileRevision = UInt64(coder.decodeInt64(forKey: "profileRevision"))
        privateCIDRs = cidrs
    }

    func encode(with coder: NSCoder) {
        coder.encode(reference, forKey: "reference")
        coder.encode(sidecarInstanceID as NSString, forKey: "sidecarInstanceID")
        coder.encode(interfaceName as NSString, forKey: "interfaceName")
        coder.encode(tunnelOperationID as NSString, forKey: "tunnelOperationID")
        coder.encode(Int(mtu), forKey: "mtu")
        coder.encode(Int64(profileRevision), forKey: "profileRevision")
        coder.encode(privateCIDRs as NSArray, forKey: "privateCIDRs")
    }

    func isValid() -> Bool {
        let suffix = interfaceName.hasPrefix("utun") ? interfaceName.dropFirst(4) : ""
        return reference.isValid()
            && validIdentifier(sidecarInstanceID)
            && !suffix.isEmpty && suffix.allSatisfy(\.isNumber)
            && tunnelOperationID == "\(reference.operationID).prepare"
            && mtu == 1420 && profileRevision > 0
            && !privateCIDRs.isEmpty && privateCIDRs.count <= 64
            && Set(privateCIDRs).count == privateCIDRs.count
            && privateCIDRs.allSatisfy(validCIDR)
    }
}

@objc(KCRReply)
final class HelperReply: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let state: String
    let errorCode: String?

    init(state: String, errorCode: String? = nil) {
        self.state = state
        self.errorCode = errorCode
    }

    required init?(coder: NSCoder) {
        guard let state = coder.decodeObject(of: NSString.self, forKey: "state") as String? else { return nil }
        self.state = state
        errorCode = coder.decodeObject(of: NSString.self, forKey: "errorCode") as String?
    }

    func encode(with coder: NSCoder) {
        coder.encode(state as NSString, forKey: "state")
        if let errorCode { coder.encode(errorCode as NSString, forKey: "errorCode") }
    }
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

private struct JournalOwner: Codable, Equatable {
    let leaseID: String
    let operationID: String
    let sidecarInstanceID: String
    let interfaceName: String
    let tunnelOperationID: String
    let mtu: UInt16
    let profileRevision: UInt64
    let privateCIDRs: [String]

    init(_ owner: LeaseOwner) {
        leaseID = owner.reference.leaseID
        operationID = owner.reference.operationID
        sidecarInstanceID = owner.sidecarInstanceID
        interfaceName = owner.interfaceName
        tunnelOperationID = owner.tunnelOperationID
        mtu = owner.mtu
        profileRevision = owner.profileRevision
        privateCIDRs = owner.privateCIDRs
    }
}

private struct RouteJournal: Codable {
    let version: UInt8
    var owner: JournalOwner
    var pendingCIDR: String?
    var appliedCIDRs: [String]
}

private protocol RouteExecuting {
    func canAdd(cidr: String, interfaceName: String) -> Bool
    func mutate(action: String, cidr: String, interfaceName: String) -> Bool
}

private struct SystemRouteExecutor: RouteExecuting {
    func canAdd(cidr: String, interfaceName: String) -> Bool {
        guard validCIDR(cidr), validInterface(interfaceName) else { return false }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/sbin/route")
        var arguments = ["-n", "get"]
        if cidr.contains(":") { arguments.append("-inet6") }
        arguments += ["-net", cidr]
        task.arguments = arguments
        task.standardInput = FileHandle.nullDevice
        let output = Pipe()
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        do { try task.run(); task.waitUntilExit() } catch { return false }
        if task.terminationStatus != 0 { return true }
        // The system default underlay is expected and does not conflict. Any
        // more-specific route returned by the kernel is owned by another
        // subsystem until this transaction has recorded it.
        let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard text.contains("destination:") else { return true }
        return text.contains("destination: default") || text.contains("destination: ::/0")
    }

    func mutate(action: String, cidr: String, interfaceName: String) -> Bool {
        guard action == "add" || action == "delete", validCIDR(cidr), validInterface(interfaceName) else { return false }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/sbin/route")
        var arguments = ["-n", action]
        if cidr.contains(":") { arguments.append("-inet6") }
        arguments += ["-net", cidr, "-interface", interfaceName]
        task.arguments = arguments
        task.standardInput = FileHandle.nullDevice
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        do { try task.run(); task.waitUntilExit() } catch { return false }
        return task.terminationStatus == 0
    }
}

private final class RouteCoordinator {
    static let shared = RouteCoordinator()
    private let lock = NSLock()
    private let executor: RouteExecuting
    private let journalURL: URL
    private var journal: RouteJournal?
    private var journalCorrupt = false
    private var heartbeatDeadline = Date.distantPast
    private var timer: DispatchSourceTimer?

    init(executor: RouteExecuting = SystemRouteExecutor(), journalURL: URL = URL(fileURLWithPath: "/Library/Application Support/KyClash/route-lease-v1.plist")) {
        self.executor = executor
        self.journalURL = journalURL
        if FileManager.default.fileExists(atPath: journalURL.path) {
            do {
                let data = try Data(contentsOf: journalURL)
                let decoded = try PropertyListDecoder().decode(RouteJournal.self, from: data)
                guard decoded.version == 1 else { throw CocoaError(.fileReadCorruptFile) }
                journal = decoded
            } catch {
                journalCorrupt = true
                journal = nil
            }
        }
        if journal != nil { _ = rollbackLocked() }
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

    func discover() -> HelperReply {
        lock.withLock {
            if journalCorrupt { return HelperReply(state: "failed_closed", errorCode: "journal_corrupt") }
            return journal == nil ? HelperReply(state: "idle") : HelperReply(state: "failed_closed", errorCode: "recovery_required")
        }
    }

    func begin(_ owner: LeaseOwner) -> HelperReply {
        lock.withLock {
            guard !journalCorrupt, owner.isValid(), journal == nil else { return HelperReply(state: "failed_closed", errorCode: "invalid_owner") }
            let candidate = RouteJournal(version: 1, owner: JournalOwner(owner), pendingCIDR: nil, appliedCIDRs: [])
            guard owner.privateCIDRs.allSatisfy({ executor.canAdd(cidr: $0, interfaceName: owner.interfaceName) }) else {
                return HelperReply(state: "failed_closed", errorCode: "route_conflict")
            }
            guard persist(candidate) else { return HelperReply(state: "failed_closed", errorCode: "journal_write_failed") }
            journal = candidate
            heartbeatDeadline = Date().addingTimeInterval(15)
            return HelperReply(state: "prepared")
        }
    }

    func apply(_ reference: LeaseReference) -> HelperReply {
        lock.withLock {
            guard valid(reference), var current = journal else { return ownershipFailure() }
            for cidr in current.owner.privateCIDRs where !current.appliedCIDRs.contains(cidr) {
                current.pendingCIDR = cidr
                guard persist(current) else { _ = rollbackLocked(); return HelperReply(state: "failed_closed", errorCode: "journal_write_failed") }
                journal = current
                guard executor.mutate(action: "add", cidr: cidr, interfaceName: current.owner.interfaceName) else {
                    current.pendingCIDR = nil
                    journal = current
                    _ = persist(current)
                    _ = rollbackLocked(); return HelperReply(state: "failed_closed", errorCode: "route_apply_failed")
                }
                current.appliedCIDRs.append(cidr)
                current.pendingCIDR = nil
                guard persist(current) else { journal = current; _ = rollbackLocked(); return HelperReply(state: "failed_closed", errorCode: "journal_write_failed") }
                journal = current
            }
            return HelperReply(state: "applied")
        }
    }

    func rollback(_ reference: LeaseReference) -> HelperReply {
        lock.withLock {
            guard valid(reference) else { return ownershipFailure() }
            return rollbackLocked() ? HelperReply(state: "idle") : HelperReply(state: "failed_closed", errorCode: "rollback_failed")
        }
    }

    func recover(_ owner: LeaseOwner) -> HelperReply {
        lock.withLock {
            guard owner.isValid(), journal?.owner == JournalOwner(owner) else { return HelperReply(state: "failed_closed", errorCode: "ownership_mismatch") }
            heartbeatDeadline = Date().addingTimeInterval(15)
            return HelperReply(state: journal?.appliedCIDRs.count == journal?.owner.privateCIDRs.count ? "applied" : "prepared")
        }
    }

    func heartbeat(_ reference: LeaseReference) -> HelperReply {
        lock.withLock {
            guard valid(reference) else { return ownershipFailure() }
            heartbeatDeadline = Date().addingTimeInterval(15)
            return statusLocked()
        }
    }

    func status(_ reference: LeaseReference) -> HelperReply {
        lock.withLock { valid(reference) ? statusLocked() : ownershipFailure() }
    }

    func invalidate(_ reference: LeaseReference?) {
        lock.withLock {
            guard let reference, valid(reference) else { return }
            _ = rollbackLocked()
        }
    }

    private func statusLocked() -> HelperReply {
        guard let journal else { return HelperReply(state: "idle") }
        return HelperReply(state: journal.appliedCIDRs.count == journal.owner.privateCIDRs.count ? "applied" : "prepared")
    }

    private func valid(_ reference: LeaseReference) -> Bool {
        reference.isValid() && reference.leaseID == journal?.owner.leaseID && reference.operationID == journal?.owner.operationID
    }

    private func ownershipFailure() -> HelperReply { HelperReply(state: "failed_closed", errorCode: "ownership_mismatch") }

    private func expireLease() {
        lock.withLock { if journal != nil && Date() > heartbeatDeadline { _ = rollbackLocked() } }
    }

    private func rollbackLocked() -> Bool {
        guard var current = journal else { return true }
        var succeeded = true
        var owned = current.appliedCIDRs
        if let pending = current.pendingCIDR, !owned.contains(pending) { owned.append(pending) }
        for cidr in owned.reversed() {
            current.pendingCIDR = cidr
            if !persist(current) { succeeded = false; continue }
            let alreadyAbsent = executor.canAdd(cidr: cidr, interfaceName: current.owner.interfaceName)
            if alreadyAbsent || executor.mutate(action: "delete", cidr: cidr, interfaceName: current.owner.interfaceName) {
                current.appliedCIDRs.removeAll { $0 == cidr }
                current.pendingCIDR = nil
                journal = current
                if !persist(current) { succeeded = false }
            } else { succeeded = false }
        }
        if succeeded {
            journal = nil
            heartbeatDeadline = .distantPast
            do {
                try FileManager.default.removeItem(at: journalURL)
            } catch {
                if (error as NSError).code != NSFileNoSuchFileError { return false }
            }
        } else { journal = current }
        return succeeded
    }

    private func persist(_ value: RouteJournal) -> Bool {
        let directory = journalURL.deletingLastPathComponent()
        do {
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory) {
                guard isDirectory.boolValue, (try directory.resourceValues(forKeys: [.isSymbolicLinkKey])).isSymbolicLink != true else { return false }
            } else {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            }
            let data = try PropertyListEncoder().encode(value)
            try data.write(to: journalURL, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journalURL.path)
            return true
        } catch { return false }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T { lock(); defer { unlock() }; return body() }
}

private final class RouteHelperService: NSObject, RouteHelperProtocol {
    private let referenceLock = NSLock()
    private var reference: LeaseReference?

    func discover(reply: @escaping (HelperReply) -> Void) { reply(RouteCoordinator.shared.discover()) }

    func begin(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void) {
        let result = RouteCoordinator.shared.begin(owner)
        if result.state == "prepared" {
            referenceLock.withLock { reference = owner.reference }
        }
        reply(result)
    }

    func apply(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(RouteCoordinator.shared.apply(reference))
    }

    func rollback(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        let result = RouteCoordinator.shared.rollback(reference)
        if result.state == "idle" {
            referenceLock.withLock { self.reference = nil }
        }
        reply(result)
    }

    func recover(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void) {
        let result = RouteCoordinator.shared.recover(owner)
        if result.errorCode == nil {
            referenceLock.withLock { reference = owner.reference }
        }
        reply(result)
    }

    func heartbeat(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(RouteCoordinator.shared.heartbeat(reference))
    }

    func status(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(RouteCoordinator.shared.status(reference))
    }

    func invalidateConnection() {
        let activeReference = referenceLock.withLock { () -> LeaseReference? in
            let active = reference
            reference = nil
            return active
        }
        RouteCoordinator.shared.invalidate(activeReference)
    }
}

private final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier != 0 else { return false }
        connection.setCodeSigningRequirement(appRequirement)
        let service = RouteHelperService()
        connection.exportedInterface = routeHelperInterface()
        connection.exportedObject = service
        connection.invalidationHandler = { [weak service] in service?.invalidateConnection() }
        connection.interruptionHandler = { [weak service] in service?.invalidateConnection() }
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

private func validCIDR(_ value: String) -> Bool {
    let pieces = value.split(separator: "/", omittingEmptySubsequences: false)
    guard pieces.count == 2, let prefix = UInt8(pieces[1]) else { return false }
    var bytes4 = in_addr(), bytes6 = in6_addr()
    let address = String(pieces[0])
    if inet_pton(AF_INET, address, &bytes4) == 1 { return prefix <= 32 && address != "0.0.0.0" }
    return inet_pton(AF_INET6, address, &bytes6) == 1 && prefix <= 128 && address != "::"
}

private func validInterface(_ value: String) -> Bool {
    let suffix = value.hasPrefix("utun") ? value.dropFirst(4) : ""
    return !suffix.isEmpty && suffix.allSatisfy(\.isNumber)
}

// This executor is used only by the explicit local/CI self-test below.  It
// never invokes `/sbin/route`; all mutations stay in memory and can be
// deterministically failed at a selected operation.  Keeping the fault
// injection at the RouteExecuting boundary lets the coordinator exercise the
// same journal/lease/rollback paths as production without touching host
// routes or requiring privileges.
private final class InjectedRouteExecutor: RouteExecuting {
    var existing: Set<String> = []
    var added: [String] = []
    var failAddAt: Int?
    var failDeleteAt: Int?
    private(set) var addCalls = 0
    private(set) var deleteCalls = 0

    func canAdd(cidr: String, interfaceName: String) -> Bool {
        validCIDR(cidr) && validInterface(interfaceName) && !existing.contains(cidr) && !added.contains(cidr)
    }

    func mutate(action: String, cidr: String, interfaceName: String) -> Bool {
        guard validCIDR(cidr), validInterface(interfaceName) else { return false }
        switch action {
        case "add":
            defer { addCalls += 1 }
            guard failAddAt != addCalls, canAdd(cidr: cidr, interfaceName: interfaceName) else { return false }
            added.append(cidr)
            return true
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

private enum RouteCoordinatorSelfTestError: Error {
    case failed(String)
}

private func requireSelfTest(_ condition: @autoclosure () -> Bool, _ description: String) throws {
    guard condition() else { throw RouteCoordinatorSelfTestError.failed(description) }
}

private func selfTestOwner(_ cidrs: [String]) -> LeaseOwner {
    let reference = LeaseReference(version: protocolVersion, leaseID: "lease.selftest.v1", operationID: "operation.selftest.v1")
    return LeaseOwner(
        reference: reference,
        sidecarInstanceID: "instance.selftest.v1",
        interfaceName: "utun42",
        tunnelOperationID: "operation.selftest.v1.prepare",
        mtu: 1420,
        profileRevision: 1,
        privateCIDRs: cidrs
    )
}

private func runRouteCoordinatorSelfTest() -> Bool {
    do {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("kyclash-route-helper-self-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                 attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }

        let cidrs = ["10.64.0.0/16", "fd00:64::/48"]
        let owner = selfTestOwner(cidrs)

        // Normal IPv4+IPv6 cycle, duplicate messages, replay mismatch, and
        // explicit connection invalidation all remain idempotent.
        let normalExecutor = InjectedRouteExecutor()
        let normal = RouteCoordinator(executor: normalExecutor, journalURL: root.appendingPathComponent("normal.plist"))
        try requireSelfTest(normal.discover().state == "idle", "normal discover must start idle")
        try requireSelfTest(normal.begin(owner).state == "prepared", "normal begin must prepare")
        try requireSelfTest(normal.apply(owner.reference).state == "applied", "normal apply must apply both families")
        try requireSelfTest(normal.apply(owner.reference).state == "applied", "duplicate apply must be idempotent")
        let replay = LeaseReference(version: protocolVersion, leaseID: "lease.replayed.v1", operationID: owner.reference.operationID)
        try requireSelfTest(normal.status(replay).errorCode == "ownership_mismatch", "replayed lease must be rejected")
        normal.invalidate(owner.reference)
        try requireSelfTest(normal.discover().state == "idle" && normalExecutor.added.isEmpty,
                            "connection invalidation must remove owned routes")

        // A pre-existing exact route is a conflict and must be rejected before
        // a journal is written or any mutation is attempted.
        let conflictExecutor = InjectedRouteExecutor()
        conflictExecutor.existing = [cidrs[0]]
        let conflict = RouteCoordinator(executor: conflictExecutor, journalURL: root.appendingPathComponent("conflict.plist"))
        try requireSelfTest(conflict.begin(owner).errorCode == "route_conflict", "exact pre-existing route must conflict")
        try requireSelfTest(conflictExecutor.added.isEmpty, "conflict must not mutate routes")

        // Inject failure before each add.  The coordinator must journal the
        // pending route and roll back every route it already added.
        for failAt in 0...1 {
            let executor = InjectedRouteExecutor()
            executor.failAddAt = failAt
            let coordinator = RouteCoordinator(executor: executor,
                                                journalURL: root.appendingPathComponent("add-failure-\(failAt).plist"))
            try requireSelfTest(coordinator.begin(owner).state == "prepared", "faulted begin must prepare")
            try requireSelfTest(coordinator.apply(owner.reference).errorCode == "route_apply_failed",
                                "add failure \(failAt) must fail closed")
            try requireSelfTest(executor.added.isEmpty, "add failure \(failAt) leaked a route")
        }

        // Force rollback itself to fail once, verify the stronger error is
        // surfaced, then retry after the injected fault is consumed.
        let rollbackExecutor = InjectedRouteExecutor()
        let rollback = RouteCoordinator(executor: rollbackExecutor, journalURL: root.appendingPathComponent("rollback-failure.plist"))
        try requireSelfTest(rollback.begin(owner).state == "prepared", "rollback fault begin must prepare")
        try requireSelfTest(rollback.apply(owner.reference).state == "applied", "rollback fault apply must apply")
        rollbackExecutor.failDeleteAt = rollbackExecutor.deleteCalls
        try requireSelfTest(rollback.rollback(owner.reference).errorCode == "rollback_failed",
                            "rollback failure must be surfaced")
        rollbackExecutor.failDeleteAt = nil
        try requireSelfTest(rollback.rollback(owner.reference).state == "idle", "rollback retry must recover")
        try requireSelfTest(rollbackExecutor.added.isEmpty, "rollback retry must remove all routes")

        // Simulate helper restart with a durable applied journal and in-memory
        // routes.  A new coordinator must reconcile them before accepting a
        // discover request.
        let restartPath = root.appendingPathComponent("restart.plist")
        let restartExecutor = InjectedRouteExecutor()
        do {
            let first = RouteCoordinator(executor: restartExecutor, journalURL: restartPath)
            try requireSelfTest(first.begin(owner).state == "prepared", "restart begin must prepare")
            try requireSelfTest(first.apply(owner.reference).state == "applied", "restart apply must apply")
        }
        try requireSelfTest(!restartExecutor.added.isEmpty, "restart fixture must leave durable routes")
        let restarted = RouteCoordinator(executor: restartExecutor, journalURL: restartPath)
        try requireSelfTest(restarted.discover().state == "idle" && restartExecutor.added.isEmpty,
                            "helper restart must recover routes before discover")

        // Corrupt journals fail closed and never attempt route mutation.
        let corruptPath = root.appendingPathComponent("corrupt.plist")
        try Data("not-a-property-list".utf8).write(to: corruptPath, options: [.atomic])
        let corruptExecutor = InjectedRouteExecutor()
        let corrupt = RouteCoordinator(executor: corruptExecutor, journalURL: corruptPath)
        try requireSelfTest(corrupt.discover().errorCode == "journal_corrupt", "corrupt journal must fail closed")
        try requireSelfTest(corruptExecutor.added.isEmpty, "corrupt journal must not mutate routes")

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
            let executor = SystemRouteExecutor()
            let ipv4Available = executor.canAdd(cidr: "10.127.0.0/16", interfaceName: "utun999")
            let ipv6Available = executor.canAdd(cidr: "fd00:127::/48", interfaceName: "utun999")
            guard ipv4Available && ipv6Available else {
                fputs("route_readonly_self_test_failed\n", stderr)
                exit(1)
            }
            print("route_readonly_self_test_ok")
            return
        }
        if CommandLine.arguments.contains("--route-coordinator-self-test") {
            if !runRouteCoordinatorSelfTest() { exit(1) }
            return
        }
        let delegate = ListenerDelegate()
        let listener = NSXPCListener(machServiceName: "net.kysion.kyclash.route-helper")
        listener.delegate = delegate
        listener.resume()
        RunLoop.current.run()
    }
}
