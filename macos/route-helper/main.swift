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
            && !suffix.isEmpty && suffix.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
            && tunnelOperationID == "\(reference.operationID).prepare"
            && mtu == 1420 && profileRevision > 0
            && !privateCIDRs.isEmpty && privateCIDRs.count <= 64
            && Set(privateCIDRs).count == privateCIDRs.count
            && privateCIDRs.allSatisfy(validCIDR)
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

private struct RouteInspection {
    let ownedExact: Bool
    let foreignConflict: Bool

    var isAvailable: Bool { !ownedExact && !foreignConflict }
}

private protocol RouteExecuting {
    func inspect(cidrs: [String], interfaceName: String) -> [String: RouteInspection]?
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
    func inspect(cidrs: [String], interfaceName: String) -> [String: RouteInspection]? {
        inspectSystemRoutes(cidrs: cidrs, interfaceName: interfaceName)
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

private func isUnspecifiedOrMulticast(_ network: ParsedRouteNetwork) -> Bool {
    let allZero = network.bytes.allSatisfy { $0 == 0 }
    let multicast = network.ipv4 ? network.bytes.first.map { $0 >= 224 } == true : network.bytes.first == 0xff
    return allZero || multicast
}

private func routeConflicts(target: ParsedRouteNetwork, existing: ParsedRouteNetwork) -> Bool {
    existing.prefix > 0 && networksOverlap(target, existing)
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
    entries: [RouteTableEntry]
) -> [String: RouteInspection] {
    targets.mapValues { target in
        var ownedExact = false
        var foreignConflict = false
        for entry in entries where routeConflicts(target: target, existing: entry.network) {
            if networksEqual(target, entry.network), entry.interfaceName == interfaceName {
                ownedExact = true
            } else {
                foreignConflict = true
            }
        }
        return RouteInspection(ownedExact: ownedExact, foreignConflict: foreignConflict)
    }
}

private func inspectSystemRoutes(cidrs: [String], interfaceName: String) -> [String: RouteInspection]? {
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
    return inspectRoutes(targets: targets, interfaceName: interfaceName, entries: entries)
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
    let inspected = inspectRoutes(targets: ["192.0.2.0/24": target4], interfaceName: "utun42", entries: entries)
    guard inspected["192.0.2.0/24"]?.ownedExact == true,
          inspected["192.0.2.0/24"]?.foreignConflict == true
    else { return false }
    return routeConflicts(target: target6, existing: moreSpecific6)
        && routeConflicts(target: target6, existing: lessSpecific6)
        && !routeConflicts(target: target6, existing: disjoint6)
}

private func removeJournalFile(_ url: URL) -> Bool {
    do {
        try FileManager.default.removeItem(at: url)
        return true
    } catch {
        return (error as NSError).code == NSFileNoSuchFileError
    }
}

private func isSymbolicLink(_ url: URL) -> Bool {
    // `destinationOfSymbolicLink` uses lstat semantics and also detects a
    // broken link.  The helper must never read or atomically replace a journal
    // path supplied as a symlink, even when its destination is absent.
    (try? FileManager.default.destinationOfSymbolicLink(atPath: url.path)) != nil
}

private final class RouteCoordinator {
    static let shared = RouteCoordinator()
    private let lock = NSLock()
    private let executor: RouteExecuting
    private let journalURL: URL
    private let removeJournal: (URL) -> Bool
    private var journal: RouteJournal?
    private var journalCorrupt = false
    private var lastCompletedReference: LeaseReference?
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
        if isSymbolicLink(journalURL) {
            journalCorrupt = true
        } else if FileManager.default.fileExists(atPath: journalURL.path) {
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
            guard let inspections = executor.inspect(cidrs: owner.privateCIDRs, interfaceName: owner.interfaceName),
                  owner.privateCIDRs.allSatisfy({ inspections[$0]?.isAvailable == true })
            else {
                return HelperReply(state: "failed_closed", errorCode: "route_conflict")
            }
            let candidate = RouteJournal(version: 1, owner: JournalOwner(owner), pendingCIDR: nil, appliedCIDRs: [])
            guard persist(candidate) else { return HelperReply(state: "failed_closed", errorCode: "journal_write_failed") }
            journal = candidate
            lastCompletedReference = nil
            heartbeatDeadline = Date().addingTimeInterval(15)
            return HelperReply(state: "prepared")
        }
    }

    func apply(_ reference: LeaseReference) -> HelperReply {
        lock.withLock {
            guard valid(reference), var current = journal else { return ownershipFailure() }
            let remaining = current.owner.privateCIDRs.filter { !current.appliedCIDRs.contains($0) }
            if !remaining.isEmpty {
                guard let preflight = executor.inspect(cidrs: remaining, interfaceName: current.owner.interfaceName),
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
            guard let postflight = executor.inspect(cidrs: current.owner.privateCIDRs, interfaceName: current.owner.interfaceName),
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

    func rollback(_ reference: LeaseReference) -> HelperReply {
        lock.withLock {
            if journal == nil, lastCompletedReference.map({ referencesEqual($0, reference) }) == true {
                return HelperReply(state: "idle")
            }
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

    // Test-only trigger used by the no-privilege coordinator matrix.  It
    // drives the same lease-expiry path as the timer without sleeping for the
    // production 15-second heartbeat window.
    func expireLeaseForSelfTest() {
        lock.withLock { heartbeatDeadline = .distantPast }
        expireLease()
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
        var owned = current.appliedCIDRs
        if let pending = current.pendingCIDR, !owned.contains(pending) { owned.append(pending) }
        guard let inspections = executor.inspect(cidrs: owned, interfaceName: current.owner.interfaceName),
              owned.allSatisfy({ inspections[$0] != nil })
        else {
            return false
        }
        for cidr in owned.reversed() {
            current.pendingCIDR = cidr
            guard persist(current) else {
                // Keep the unresolved pending marker in memory and stop.  A
                // later route must not overwrite it when the durable write
                // itself failed.
                journal = current
                return false
            }
            guard let inspection = inspections[cidr] else {
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
            let pendingState = current
            current.appliedCIDRs.removeAll { $0 == cidr }
            current.pendingCIDR = nil
            guard persist(current) else {
                // Keep the pre-delete durable state, including the pending
                // marker, until the post-delete journal write succeeds.  If
                // the command's success was ambiguous, the next retry can
                // inspect and delete the route instead of treating it as
                // already absent.
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
        journal = nil
        heartbeatDeadline = .distantPast
        return true
    }

    private func persist(_ value: RouteJournal) -> Bool {
        let directory = journalURL.deletingLastPathComponent()
        do {
            guard !isSymbolicLink(journalURL) else { return false }
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

private func referencesEqual(_ lhs: LeaseReference, _ rhs: LeaseReference) -> Bool {
    lhs.version == rhs.version && lhs.leaseID == rhs.leaseID && lhs.operationID == rhs.operationID
}

private func validCIDR(_ value: String) -> Bool {
    let pieces = value.split(separator: "/", omittingEmptySubsequences: false)
    guard pieces.count == 2,
          !pieces[0].isEmpty,
          !pieces[1].isEmpty,
          value == value.trimmingCharacters(in: .whitespacesAndNewlines),
          !value.contains("%"),
          pieces[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          UInt8(pieces[1]) != nil
    else { return false }
    guard let network = parseRouteNetwork(value), network.prefix > 0,
          isCanonicalNetwork(network), !isUnspecifiedOrMulticast(network)
    else { return false }
    return true
}

private func validInterface(_ value: String) -> Bool {
    let suffix = value.hasPrefix("utun") ? value.dropFirst(4) : ""
    return !suffix.isEmpty && suffix.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
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
    var failAddAfterMutationAt: Int?
    var failDeleteAt: Int?
    private(set) var addCalls = 0
    private(set) var deleteCalls = 0

    func inspect(cidrs: [String], interfaceName: String) -> [String: RouteInspection]? {
        guard validInterface(interfaceName), cidrs.allSatisfy(validCIDR) else { return nil }
        return Dictionary(uniqueKeysWithValues: cidrs.map { cidr in
            (cidr, RouteInspection(ownedExact: added.contains(cidr), foreignConflict: existing.contains(cidr)))
        })
    }

    func mutate(action: String, cidr: String, interfaceName: String) -> Bool {
        guard validCIDR(cidr), validInterface(interfaceName) else { return false }
        switch action {
        case "add":
            defer { addCalls += 1 }
            guard failAddAt != addCalls,
                  inspect(cidrs: [cidr], interfaceName: interfaceName)?[cidr]?.isAvailable == true
            else { return false }
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

        // Default-route takeover is never a valid KyClash private route. Keep
        // the refusal explicit in the in-memory helper gate so a future CIDR
        // parser change cannot silently widen the mutation scope.
        let defaultRouteExecutor = InjectedRouteExecutor()
        try requireSelfTest(defaultRouteExecutor.inspect(cidrs: ["0.0.0.0/0"], interfaceName: "utun42") == nil,
                            "IPv4 default route must be refused")
        try requireSelfTest(defaultRouteExecutor.inspect(cidrs: ["::/0"], interfaceName: "utun42") == nil,
                            "IPv6 default route must be refused")
        for invalidCIDR in [
            "1.2.3.4/0", "224.0.0.0/4", "ff00::/8", "10.0.0.1/24",
            "10.0.0.0/nope", "10.0.0.0", "10.0.0.0/+24", "fd00::%utun4/48"
        ] {
            try requireSelfTest(InjectedRouteExecutor().inspect(cidrs: [invalidCIDR], interfaceName: "utun42") == nil,
                                "invalid/non-canonical CIDR must be refused: \(invalidCIDR)")
        }
        let overlappingOwner = selfTestOwner(["10.64.0.0/16", "10.64.1.0/24"])
        try requireSelfTest(!overlappingOwner.isValid(), "overlapping desired CIDRs must be refused")

        // Normal IPv4+IPv6 cycle, duplicate messages, replay mismatch, and
        // explicit connection invalidation all remain idempotent.
        let normalExecutor = InjectedRouteExecutor()
        let normal = RouteCoordinator(executor: normalExecutor, journalURL: root.appendingPathComponent("normal.plist"))
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
        normal.invalidate(owner.reference)
        try requireSelfTest(normal.discover().state == "idle" && normalExecutor.added.isEmpty,
                            "connection invalidation must remove owned routes")

        // A prepared lease has no applied or pending CIDR yet.  Rollback must
        // still remove its journal, and a duplicate rollback must remain
        // idempotent instead of failing on an empty inspection set.
        let preparedExecutor = InjectedRouteExecutor()
        let preparedRollback = RouteCoordinator(
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
        let symlinkCoordinator = RouteCoordinator(
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

        // A route command may report failure after the kernel has already
        // installed the route.  The durable pending CIDR must remain until
        // exact-state inspection proves the owned route was removed.
        let ambiguousExecutor = InjectedRouteExecutor()
        ambiguousExecutor.failAddAfterMutationAt = 1
        let ambiguous = RouteCoordinator(executor: ambiguousExecutor,
                                         journalURL: root.appendingPathComponent("ambiguous-add.plist"))
        try requireSelfTest(ambiguous.begin(owner).state == "prepared", "ambiguous begin must prepare")
        try requireSelfTest(ambiguous.apply(owner.reference).errorCode == "route_apply_failed",
                            "ambiguous add must fail closed")
        try requireSelfTest(ambiguousExecutor.added.isEmpty, "ambiguous add leaked a route")

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

        // A durable write failure before the first delete must stop the
        // rollback with its pending marker intact; it must not continue to a
        // later CIDR and overwrite the unresolved state.  Removing the test
        // symlink permits a deterministic retry and proves recovery remains
        // possible once persistence is available again.
        let persistFailurePath = root.appendingPathComponent("rollback-persist-failure.plist")
        let persistFailureTarget = root.appendingPathComponent("rollback-persist-target.plist")
        let persistFailureExecutor = InjectedRouteExecutor()
        let persistFailure = RouteCoordinator(
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
        let foreign = RouteCoordinator(executor: foreignExecutor, journalURL: root.appendingPathComponent("foreign-after-apply.plist"))
        try requireSelfTest(foreign.begin(owner).state == "prepared", "foreign begin must prepare")
        try requireSelfTest(foreign.apply(owner.reference).state == "applied", "foreign apply must apply")
        foreignExecutor.existing.insert(cidrs[0])
        try requireSelfTest(foreign.rollback(owner.reference).state == "idle", "foreign rollback must remove owned state")
        try requireSelfTest(foreignExecutor.added.isEmpty && foreignExecutor.existing == [cidrs[0]],
                            "foreign rollback must preserve the foreign route")

        let foreignOnlyExecutor = InjectedRouteExecutor()
        let foreignOnly = RouteCoordinator(
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
        let unlink = RouteCoordinator(
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
            _ = executor.inspect(cidrs: ["10.127.0.0/16"], interfaceName: "utun999")
            _ = executor.inspect(cidrs: ["fd00:127::/48"], interfaceName: "utun999")
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
