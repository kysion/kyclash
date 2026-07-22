import CryptoKit
import Darwin
import Foundation
import Security

private let brokerProtocolVersion: UInt8 = 1
private let routeHelperV3ProtocolVersion: UInt8 = 3
private let routeBrokerProtocolVersion: UInt8 = 1
private let brokerMachService = "net.kysion.kyclash.tunnel-broker"
private let brokerExecutableName = "kyclash-tunnel-broker"
private let sidecarExecutableName = "kyclash-network-sidecar"
private let maximumIdentifierBytes = 64
private let appRequirement = "anchor apple generic and identifier \"net.kysion.kyclash\" and certificate leaf[subject.OU] = \"RQUQ8Y3S9H\""
private let routeHelperRequirement = "anchor apple generic and identifier \"net.kysion.kyclash.route-helper\" and certificate leaf[subject.OU] = \"RQUQ8Y3S9H\""

private enum BrokerState: String {
    case idle
    case running
    case routeHeld = "route_held"
}

private enum BrokerErrorCode: String {
    case invalidRequest = "invalid_request"
    case unavailable
    case alreadyRunning = "already_running"
    case ownershipMismatch = "ownership_mismatch"
    case staleGeneration = "stale_generation"
    case routeHeld = "route_held"
    case holdMismatch = "hold_mismatch"
    case launchFailed = "launch_failed"
}

private func validIdentifier(_ value: String) -> Bool {
    (8...maximumIdentifierBytes).contains(value.utf8.count)
        && value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57)
                || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
                || byte == 45 || byte == 46 || byte == 95
        }
}

@objc(KCTunnelReference)
final class TunnelReference: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let generation: UInt64
    let sidecarInstanceID: String

    init(protocolVersion: UInt8 = brokerProtocolVersion, generation: UInt64, sidecarInstanceID: String) {
        self.protocolVersion = protocolVersion
        self.generation = generation
        self.sidecarInstanceID = sidecarInstanceID
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              coder.containsValue(forKey: "generation"),
              let instanceID = coder.decodeObject(of: NSString.self, forKey: "sidecarInstanceID") as String?
        else { return nil }
        let rawVersion = coder.decodeInteger(forKey: "protocolVersion")
        let rawGeneration = coder.decodeInt64(forKey: "generation")
        guard (0...Int(UInt8.max)).contains(rawVersion), rawGeneration > 0 else { return nil }
        protocolVersion = UInt8(rawVersion)
        generation = UInt64(rawGeneration)
        sidecarInstanceID = instanceID
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(Int64(generation), forKey: "generation")
        coder.encode(sidecarInstanceID as NSString, forKey: "sidecarInstanceID")
    }

    func isValid() -> Bool {
        protocolVersion == brokerProtocolVersion
            && generation > 0
            && generation <= UInt64(Int64.max)
            && validIdentifier(sidecarInstanceID)
    }
}

private func sameReference(_ lhs: TunnelReference, _ rhs: TunnelReference) -> Bool {
    lhs.protocolVersion == rhs.protocolVersion
        && lhs.generation == rhs.generation
        && lhs.sidecarInstanceID == rhs.sidecarInstanceID
}

@objc(KCTunnelRouteBinding)
final class TunnelRouteBinding: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let reference: TunnelReference
    let routeLeaseID: String

    init(reference: TunnelReference, routeLeaseID: String) {
        self.reference = reference
        self.routeLeaseID = routeLeaseID
    }

    required init?(coder: NSCoder) {
        guard let reference = coder.decodeObject(of: TunnelReference.self, forKey: "reference"),
              let leaseID = coder.decodeObject(of: NSString.self, forKey: "routeLeaseID") as String?
        else { return nil }
        self.reference = reference
        routeLeaseID = leaseID
    }

    func encode(with coder: NSCoder) {
        coder.encode(reference, forKey: "reference")
        coder.encode(routeLeaseID as NSString, forKey: "routeLeaseID")
    }

    func isValid() -> Bool {
        reference.isValid() && validIdentifier(routeLeaseID)
    }
}

// Route-helper v3 binds the broker reference and both route identifiers in
// one immutable NSSecureCoding value.  The old TunnelRouteBinding above is
// retained for recovery/compatibility only and can never populate this type.
@objc(KCTunnelRouteBindingV3)
final class TunnelRouteBindingV3: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let brokerProtocolVersion: UInt8
    let brokerGeneration: UInt64
    let sidecarInstanceID: String
    let routeLeaseID: String
    let operationID: String

    init(
        protocolVersion: UInt8 = routeHelperV3ProtocolVersion,
        brokerProtocolVersion: UInt8 = routeBrokerProtocolVersion,
        brokerGeneration: UInt64,
        sidecarInstanceID: String,
        routeLeaseID: String,
        operationID: String
    ) {
        self.protocolVersion = protocolVersion
        self.brokerProtocolVersion = brokerProtocolVersion
        self.brokerGeneration = brokerGeneration
        self.sidecarInstanceID = sidecarInstanceID
        self.routeLeaseID = routeLeaseID
        self.operationID = operationID
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              coder.containsValue(forKey: "brokerProtocolVersion"),
              coder.containsValue(forKey: "brokerGeneration"),
              let sidecar = coder.decodeObject(of: NSString.self, forKey: "sidecarInstanceID") as String?,
              let lease = coder.decodeObject(of: NSString.self, forKey: "routeLeaseID") as String?,
              let operation = coder.decodeObject(of: NSString.self, forKey: "operationID") as String?
        else { return nil }
        let rawProtocol = coder.decodeInteger(forKey: "protocolVersion")
        let rawBrokerProtocol = coder.decodeInteger(forKey: "brokerProtocolVersion")
        let rawGeneration = coder.decodeInt64(forKey: "brokerGeneration")
        guard (0...Int(UInt8.max)).contains(rawProtocol),
              (0...Int(UInt8.max)).contains(rawBrokerProtocol),
              rawGeneration > 0
        else { return nil }
        self.protocolVersion = UInt8(rawProtocol)
        self.brokerProtocolVersion = UInt8(rawBrokerProtocol)
        self.brokerGeneration = UInt64(rawGeneration)
        self.sidecarInstanceID = sidecar
        self.routeLeaseID = lease
        self.operationID = operation
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(Int(brokerProtocolVersion), forKey: "brokerProtocolVersion")
        coder.encode(Int64(brokerGeneration), forKey: "brokerGeneration")
        coder.encode(sidecarInstanceID as NSString, forKey: "sidecarInstanceID")
        coder.encode(routeLeaseID as NSString, forKey: "routeLeaseID")
        coder.encode(operationID as NSString, forKey: "operationID")
    }

    func isValid() -> Bool {
        protocolVersion == routeHelperV3ProtocolVersion
            && brokerProtocolVersion == routeBrokerProtocolVersion
            && brokerGeneration > 0
            && brokerGeneration <= UInt64(Int64.max)
            && validIdentifier(sidecarInstanceID)
            && validIdentifier(routeLeaseID)
            && validIdentifier(operationID)
    }
}

private func sameRouteBindingV3(_ lhs: TunnelRouteBindingV3, _ rhs: TunnelRouteBindingV3) -> Bool {
    lhs.protocolVersion == rhs.protocolVersion
        && lhs.brokerProtocolVersion == rhs.brokerProtocolVersion
        && lhs.brokerGeneration == rhs.brokerGeneration
        && lhs.sidecarInstanceID == rhs.sidecarInstanceID
        && lhs.routeLeaseID == rhs.routeLeaseID
        && lhs.operationID == rhs.operationID
}

private func sameRouteSessionV3(_ lhs: TunnelRouteBindingV3, _ rhs: TunnelRouteBindingV3) -> Bool {
    lhs.brokerProtocolVersion == rhs.brokerProtocolVersion
        && lhs.brokerGeneration == rhs.brokerGeneration
        && lhs.sidecarInstanceID == rhs.sidecarInstanceID
}

private enum RetiredRouteBindingMatch {
    case exact
    case sameSessionMismatch
    case unrelated
}

private struct RetiredRouteBindingV3Tombstone {
    private(set) var binding: TunnelRouteBindingV3?

    mutating func record(_ binding: TunnelRouteBindingV3) {
        self.binding = binding
    }

    func classify(_ candidate: TunnelRouteBindingV3) -> RetiredRouteBindingMatch {
        guard let binding else { return .unrelated }
        if sameRouteBindingV3(binding, candidate) { return .exact }
        return sameRouteSessionV3(binding, candidate) ? .sameSessionMismatch : .unrelated
    }
}

private func routeBindingV3MatchesReference(_ binding: TunnelRouteBindingV3, _ reference: TunnelReference) -> Bool {
    binding.brokerProtocolVersion == reference.protocolVersion
        && binding.brokerGeneration == reference.generation
        && binding.sidecarInstanceID == reference.sidecarInstanceID
}

@objc(KCTunnelBrokerReply)
final class TunnelBrokerReply: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let state: String
    let errorCode: String?

    fileprivate init(state: BrokerState, errorCode: BrokerErrorCode? = nil) {
        protocolVersion = brokerProtocolVersion
        self.state = state.rawValue
        self.errorCode = errorCode?.rawValue
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              let state = coder.decodeObject(of: NSString.self, forKey: "state") as String?
        else { return nil }
        let rawVersion = coder.decodeInteger(forKey: "protocolVersion")
        guard (0...Int(UInt8.max)).contains(rawVersion) else { return nil }
        protocolVersion = UInt8(rawVersion)
        self.state = state
        errorCode = coder.decodeObject(of: NSString.self, forKey: "errorCode") as String?
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(state as NSString, forKey: "state")
        if let errorCode { coder.encode(errorCode as NSString, forKey: "errorCode") }
    }
}

@objc(KCTunnelBrokerRouteReplyV3)
final class TunnelBrokerRouteReplyV3: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let brokerProtocolVersion: UInt8
    let brokerGeneration: UInt64
    let state: String
    let errorCode: String?
    let sidecarInstanceID: String
    let routeLeaseID: String
    let operationID: String

    fileprivate init(binding: TunnelRouteBindingV3, state: BrokerState, errorCode: BrokerErrorCode? = nil) {
        protocolVersion = binding.protocolVersion
        brokerProtocolVersion = binding.brokerProtocolVersion
        brokerGeneration = binding.brokerGeneration
        self.state = state.rawValue
        self.errorCode = errorCode?.rawValue
        sidecarInstanceID = binding.sidecarInstanceID
        routeLeaseID = binding.routeLeaseID
        operationID = binding.operationID
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              coder.containsValue(forKey: "brokerProtocolVersion"),
              coder.containsValue(forKey: "brokerGeneration"),
              let state = coder.decodeObject(of: NSString.self, forKey: "state") as String?,
              let sidecar = coder.decodeObject(of: NSString.self, forKey: "sidecarInstanceID") as String?,
              let lease = coder.decodeObject(of: NSString.self, forKey: "routeLeaseID") as String?,
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
        self.state = state
        errorCode = coder.decodeObject(of: NSString.self, forKey: "errorCode") as String?
        sidecarInstanceID = sidecar
        routeLeaseID = lease
        operationID = operation
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(Int(brokerProtocolVersion), forKey: "brokerProtocolVersion")
        coder.encode(Int64(brokerGeneration), forKey: "brokerGeneration")
        coder.encode(state as NSString, forKey: "state")
        if let errorCode { coder.encode(errorCode as NSString, forKey: "errorCode") }
        coder.encode(sidecarInstanceID as NSString, forKey: "sidecarInstanceID")
        coder.encode(routeLeaseID as NSString, forKey: "routeLeaseID")
        coder.encode(operationID as NSString, forKey: "operationID")
    }
}

@objc(KCTunnelSessionReply)
final class TunnelSessionReply: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let protocolVersion: UInt8
    let state: String
    let errorCode: String?
    let reference: TunnelReference?
    let inputHandle: FileHandle?
    let outputHandle: FileHandle?

    fileprivate init(
        state: BrokerState,
        errorCode: BrokerErrorCode? = nil,
        reference: TunnelReference? = nil,
        inputHandle: FileHandle? = nil,
        outputHandle: FileHandle? = nil
    ) {
        protocolVersion = brokerProtocolVersion
        self.state = state.rawValue
        self.errorCode = errorCode?.rawValue
        self.reference = reference
        self.inputHandle = inputHandle
        self.outputHandle = outputHandle
    }

    required init?(coder: NSCoder) {
        guard coder.containsValue(forKey: "protocolVersion"),
              let state = coder.decodeObject(of: NSString.self, forKey: "state") as String?
        else { return nil }
        let rawVersion = coder.decodeInteger(forKey: "protocolVersion")
        guard (0...Int(UInt8.max)).contains(rawVersion) else { return nil }
        protocolVersion = UInt8(rawVersion)
        self.state = state
        errorCode = coder.decodeObject(of: NSString.self, forKey: "errorCode") as String?
        reference = coder.decodeObject(of: TunnelReference.self, forKey: "reference")
        inputHandle = coder.decodeObject(of: FileHandle.self, forKey: "inputHandle")
        outputHandle = coder.decodeObject(of: FileHandle.self, forKey: "outputHandle")
    }

    func encode(with coder: NSCoder) {
        coder.encode(Int(protocolVersion), forKey: "protocolVersion")
        coder.encode(state as NSString, forKey: "state")
        if let errorCode { coder.encode(errorCode as NSString, forKey: "errorCode") }
        if let reference { coder.encode(reference, forKey: "reference") }
        if let inputHandle { coder.encode(inputHandle, forKey: "inputHandle") }
        if let outputHandle { coder.encode(outputHandle, forKey: "outputHandle") }
    }

    // NSXPC archives FileHandle values synchronously while the reply block is
    // invoked.  The broker must close its local copies immediately after that
    // call returns; otherwise the child retains an extra stdin writer/stdout
    // reader and an App disconnect cannot deliver EOF. The receiver owns the
    // duplicated descriptors after the reply has been encoded.
    func closeTransferredPipeCopies() {
        inputHandle?.closeFile()
        outputHandle?.closeFile()
    }
}

@objc(KCTunnelBrokerAppProtocol)
protocol TunnelBrokerAppProtocol {
    func start(reply: @escaping (TunnelSessionReply) -> Void)
    func stop(_ reference: TunnelReference, reply: @escaping (TunnelBrokerReply) -> Void)
    func status(_ reference: TunnelReference, reply: @escaping (TunnelBrokerReply) -> Void)
}

@objc(KCTunnelBrokerRouteProtocol)
protocol TunnelBrokerRouteProtocol {
    func hold(_ binding: TunnelRouteBinding, reply: @escaping (TunnelBrokerReply) -> Void)
    func release(_ binding: TunnelRouteBinding, reply: @escaping (TunnelBrokerReply) -> Void)
    func status(_ binding: TunnelRouteBinding, reply: @escaping (TunnelBrokerReply) -> Void)
}

@objc(KCTunnelBrokerRouteV3Protocol)
protocol TunnelBrokerRouteV3Protocol: TunnelBrokerRouteProtocol {
    func holdV3(_ binding: TunnelRouteBindingV3, reply: @escaping (TunnelBrokerRouteReplyV3) -> Void)
    func releaseV3(_ binding: TunnelRouteBindingV3, reply: @escaping (TunnelBrokerRouteReplyV3) -> Void)
    func statusV3(_ binding: TunnelRouteBindingV3, reply: @escaping (TunnelBrokerRouteReplyV3) -> Void)
}

private func appXPCInterface() -> NSXPCInterface {
    let interface = NSXPCInterface(with: TunnelBrokerAppProtocol.self)
    let referenceClasses = NSSet(objects: TunnelReference.self, NSString.self) as! Set<AnyHashable>
    let replyClasses = NSSet(objects: TunnelBrokerReply.self, NSString.self) as! Set<AnyHashable>
    let sessionClasses = NSSet(
        objects: TunnelSessionReply.self, TunnelReference.self, FileHandle.self, NSString.self
    ) as! Set<AnyHashable>
    interface.setClasses(
        sessionClasses,
        for: #selector(TunnelBrokerAppProtocol.start(reply:)),
        argumentIndex: 0,
        ofReply: true
    )
    for selector in [
        #selector(TunnelBrokerAppProtocol.stop(_:reply:)),
        #selector(TunnelBrokerAppProtocol.status(_:reply:)),
    ] {
        interface.setClasses(referenceClasses, for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(replyClasses, for: selector, argumentIndex: 0, ofReply: true)
    }
    return interface
}

private func routeXPCInterface() -> NSXPCInterface {
    let interface = NSXPCInterface(with: TunnelBrokerRouteV3Protocol.self)
    let bindingClasses = NSSet(
        objects: TunnelRouteBinding.self, TunnelReference.self, NSString.self
    ) as! Set<AnyHashable>
    let replyClasses = NSSet(objects: TunnelBrokerReply.self, NSString.self) as! Set<AnyHashable>
    for selector in [
        #selector(TunnelBrokerRouteProtocol.hold(_:reply:)),
        #selector(TunnelBrokerRouteProtocol.release(_:reply:)),
        #selector(TunnelBrokerRouteProtocol.status(_:reply:)),
    ] {
        interface.setClasses(bindingClasses, for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(replyClasses, for: selector, argumentIndex: 0, ofReply: true)
    }
    let bindingV3Classes = NSSet(
        objects: TunnelRouteBindingV3.self, NSString.self
    ) as! Set<AnyHashable>
    let replyV3Classes = NSSet(
        objects: TunnelBrokerRouteReplyV3.self, NSString.self
    ) as! Set<AnyHashable>
    for selector in [
        #selector(TunnelBrokerRouteV3Protocol.holdV3(_:reply:)),
        #selector(TunnelBrokerRouteV3Protocol.releaseV3(_:reply:)),
        #selector(TunnelBrokerRouteV3Protocol.statusV3(_:reply:)),
    ] {
        interface.setClasses(bindingV3Classes, for: selector, argumentIndex: 0, ofReply: false)
        interface.setClasses(replyV3Classes, for: selector, argumentIndex: 0, ofReply: true)
    }
    return interface
}

private enum LaunchPlanError: Error {
    case invalidBrokerLayout
    case invalidSidecar
}

private struct SidecarLaunchPlan: Equatable {
    let executableURL: URL
    // These values are intentionally fixed by the broker, not supplied by an
    // XPC request. Protocol-v2 bootstrap and secrets use the returned pipes.
    let arguments: [String] = []
    let environment: [String: String] = [:]
}

private protocol SidecarTrustValidating {
    func validate(sidecarAt url: URL) -> Bool
}

private struct FixedSidecarLaunchPlanner {
    let trustValidator: SidecarTrustValidating

    func plan(brokerExecutableURL: URL) throws -> SidecarLaunchPlan {
        guard brokerExecutableURL.lastPathComponent == brokerExecutableName,
              brokerExecutableURL.deletingLastPathComponent().lastPathComponent == "Resources",
              brokerExecutableURL.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent == "Contents",
              brokerExecutableURL.deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().pathExtension == "app",
              isRegularNonSymlink(brokerExecutableURL)
        else { throw LaunchPlanError.invalidBrokerLayout }

        let sidecarURL = brokerExecutableURL.deletingLastPathComponent()
            .appendingPathComponent(sidecarExecutableName, isDirectory: false)
        guard sidecarURL.deletingLastPathComponent() == brokerExecutableURL.deletingLastPathComponent(),
              isRegularNonSymlink(sidecarURL),
              trustValidator.validate(sidecarAt: sidecarURL)
        else { throw LaunchPlanError.invalidSidecar }
        return SidecarLaunchPlan(executableURL: sidecarURL)
    }
}

private func isRegularNonSymlink(_ url: URL) -> Bool {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { return false }
    return (info.st_mode & S_IFMT) == S_IFREG && info.st_nlink == 1
}

private struct ManifestSidecarTrustValidator: SidecarTrustValidating {
    func validate(sidecarAt url: URL) -> Bool {
        guard TunnelBrokerBuildManifest.sidecarArchitecture == "arm64",
              TunnelBrokerBuildManifest.sidecarTeamID == "RQUQ8Y3S9H",
              TunnelBrokerBuildManifest.sidecarSHA256.utf8.count == 64,
              let data = try? Data(contentsOf: url, options: [.mappedIfSafe]),
              data.count >= 8,
              isThinArm64MachO(data),
              SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined()
                == TunnelBrokerBuildManifest.sidecarSHA256,
              validCodeSignature(at: url)
        else { return false }
        return true
    }

    private func isThinArm64MachO(_ data: Data) -> Bool {
        let bytes = [UInt8](data.prefix(8))
        guard bytes == Array(data.prefix(8)), bytes.count == 8 else { return false }
        let magic = UInt32(bytes[0])
            | UInt32(bytes[1]) << 8
            | UInt32(bytes[2]) << 16
            | UInt32(bytes[3]) << 24
        let cpuType = UInt32(bytes[4])
            | UInt32(bytes[5]) << 8
            | UInt32(bytes[6]) << 16
            | UInt32(bytes[7]) << 24
        return magic == 0xfeedfacf && cpuType == 0x0100000c
    }

    private func validCodeSignature(at url: URL) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode
        else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            TunnelBrokerBuildManifest.sidecarDesignatedRequirement as CFString,
            [],
            &requirement
        ) == errSecSuccess,
            let requirement,
            SecStaticCodeCheckValidity(
                staticCode,
                SecCSFlags(rawValue: kSecCSStrictValidate),
                requirement
            ) == errSecSuccess
        else { return false }

        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
            let information = rawInformation as? [String: Any],
            information[kSecCodeInfoTeamIdentifier as String] as? String
                == TunnelBrokerBuildManifest.sidecarTeamID
        else { return false }
        return true
    }
}

private final class SidecarChild {
    let process: Process
    let inputHandle: FileHandle
    let outputHandle: FileHandle
    private let exited = DispatchSemaphore(value: 0)
    private let pipeLock = NSLock()
    private var brokerPipeCopiesClosed = false

    init(plan: SidecarLaunchPlan, onExit: @escaping () -> Void) throws {
        let inputPipe = Pipe()
        let outputPipe = Pipe()
        process = Process()
        inputHandle = inputPipe.fileHandleForWriting
        outputHandle = outputPipe.fileHandleForReading
        process.executableURL = plan.executableURL
        process.arguments = plan.arguments
        process.environment = plan.environment
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [exited] _ in
            exited.signal()
            onExit()
        }
        try process.run()
        inputPipe.fileHandleForReading.closeFile()
        outputPipe.fileHandleForWriting.closeFile()
    }

    @discardableResult
    func stopAndReap() -> Bool {
        closeBrokerPipeCopies()
        if process.isRunning, exited.wait(timeout: .now() + .milliseconds(250)) == .timedOut {
            process.terminate()
        }
        if process.isRunning, exited.wait(timeout: .now() + .seconds(2)) == .timedOut {
            let pid = process.processIdentifier
            if pid > 1 { _ = Darwin.kill(pid, SIGKILL) }
        }
        if process.isRunning { _ = exited.wait(timeout: .now() + .seconds(2)) }
        // `Process.isRunning == false` is the broker's exact local reap
        // boundary.  Callers must not clear the active generation before this
        // proof; an unbounded/ambiguous stop remains recovery-only.
        return !process.isRunning
    }

    func closeBrokerPipeCopies() {
        pipeLock.lock()
        guard !brokerPipeCopiesClosed else {
            pipeLock.unlock()
            return
        }
        brokerPipeCopiesClosed = true
        inputHandle.closeFile()
        outputHandle.closeFile()
        pipeLock.unlock()
    }
}

private struct SessionLeaseState {
    let reference: TunnelReference
    let appConnectionID: UUID
    var appConnected = true
    var routeLeaseID: String?
    var releasedLegacyRouteLeaseID: String?
    var routeBindingV3: TunnelRouteBindingV3?
    var releasedRouteBindingV3: TunnelRouteBindingV3?

    var hasRouteHold: Bool { routeLeaseID != nil || routeBindingV3 != nil }

    mutating func hold(_ binding: TunnelRouteBinding) -> BrokerErrorCode? {
        guard binding.isValid(), sameReference(binding.reference, reference) else {
            return .staleGeneration
        }
        // A legacy lease is recovery-only once a v3 hold exists. It may not
        // become a second authority for the same broker generation.
        guard releasedLegacyRouteLeaseID == nil,
              routeBindingV3 == nil,
              releasedRouteBindingV3 == nil
        else { return .holdMismatch }
        guard routeLeaseID == nil || routeLeaseID == binding.routeLeaseID else {
            return .holdMismatch
        }
        routeLeaseID = binding.routeLeaseID
        return nil
    }

    mutating func release(_ binding: TunnelRouteBinding) -> BrokerErrorCode? {
        guard binding.isValid(), sameReference(binding.reference, reference) else {
            return .staleGeneration
        }
        if let released = releasedLegacyRouteLeaseID {
            return released == binding.routeLeaseID ? nil : .holdMismatch
        }
        guard routeLeaseID == binding.routeLeaseID else { return .holdMismatch }
        routeLeaseID = nil
        releasedLegacyRouteLeaseID = binding.routeLeaseID
        return nil
    }

    mutating func holdV3(_ binding: TunnelRouteBindingV3) -> BrokerErrorCode? {
        guard binding.isValid(), routeBindingV3MatchesReference(binding, reference) else {
            return .staleGeneration
        }
        guard routeLeaseID == nil, releasedLegacyRouteLeaseID == nil else { return .holdMismatch }
        if let current = routeBindingV3 {
            return sameRouteBindingV3(current, binding) ? nil : .holdMismatch
        }
        guard releasedRouteBindingV3 == nil else { return .holdMismatch }
        routeBindingV3 = binding
        return nil
    }

    mutating func releaseV3(_ binding: TunnelRouteBindingV3) -> BrokerErrorCode? {
        guard binding.isValid(), routeBindingV3MatchesReference(binding, reference) else {
            return .staleGeneration
        }
        guard routeLeaseID == nil, releasedLegacyRouteLeaseID == nil else { return .holdMismatch }
        if let released = releasedRouteBindingV3 {
            return sameRouteBindingV3(released, binding) ? nil : .holdMismatch
        }
        if let current = routeBindingV3 {
            guard sameRouteBindingV3(current, binding) else { return .holdMismatch }
            routeBindingV3 = nil
        }
        // Exact current session with no legacy/v3 hold or history is the
        // safe no-op release for a durable hold_pending record whose hold
        // request never reached the broker. Record the full tuple so a lost
        // reply can be retried but a different tuple cannot claim absence.
        releasedRouteBindingV3 = binding
        return nil
    }

    func statusV3(_ binding: TunnelRouteBindingV3) -> BrokerErrorCode? {
        guard binding.isValid(), routeBindingV3MatchesReference(binding, reference) else {
            return .staleGeneration
        }
        guard routeLeaseID == nil, releasedLegacyRouteLeaseID == nil else { return .holdMismatch }
        if let current = routeBindingV3, sameRouteBindingV3(current, binding) { return nil }
        if let released = releasedRouteBindingV3, sameRouteBindingV3(released, binding) { return nil }
        return .holdMismatch
    }
}

private final class TunnelBrokerCoordinator {
    static let shared = TunnelBrokerCoordinator()

    private struct ActiveSession {
        var lease: SessionLeaseState
        let child: SidecarChild
    }

    private let lock = NSLock()
    private var nextGeneration: UInt64 = 1
    private var active: ActiveSession?
    // One bounded exact v3 tombstone lets a helper retry release/status after
    // a reply loss without treating stale_generation as positive reap proof.
    private var retiredRouteBindingV3 = RetiredRouteBindingV3Tombstone()
    private let planner = FixedSidecarLaunchPlanner(trustValidator: ManifestSidecarTrustValidator())

    func start(appConnectionID: UUID) -> TunnelSessionReply {
        lock.lock()
        defer { lock.unlock() }
        guard active == nil else {
            return TunnelSessionReply(state: currentStateLocked(), errorCode: .alreadyRunning)
        }
        guard nextGeneration <= UInt64(Int64.max) else {
            return TunnelSessionReply(state: .idle, errorCode: .unavailable)
        }
        let reference = TunnelReference(
            generation: nextGeneration,
            sidecarInstanceID: UUID().uuidString.lowercased()
        )
        nextGeneration += 1
        // A launchd BundleProgram is not guaranteed to expose an application
        // `Bundle.main` object.  Use the process executable as the same fixed
        // bundle-relative anchor, while still requiring the sealed
        // `*.app/Contents/Resources` layout in the planner.
        let executableURL = Bundle.main.executableURL
            ?? URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
        guard executableURL.lastPathComponent == brokerExecutableName,
              let plan = try? planner.plan(brokerExecutableURL: executableURL)
        else { return TunnelSessionReply(state: .idle, errorCode: .unavailable) }

        let child: SidecarChild
        do {
            child = try SidecarChild(plan: plan) { [weak self] in
                self?.childExited(reference: reference)
            }
        } catch {
            return TunnelSessionReply(state: .idle, errorCode: .launchFailed)
        }
        active = ActiveSession(
            lease: SessionLeaseState(reference: reference, appConnectionID: appConnectionID),
            child: child
        )
        return TunnelSessionReply(
            state: .running,
            reference: reference,
            inputHandle: child.inputHandle,
            outputHandle: child.outputHandle
        )
    }

    func stop(_ reference: TunnelReference, appConnectionID: UUID) -> TunnelBrokerReply {
        let child: SidecarChild?
        lock.lock()
        guard reference.isValid(), let session = active else {
            lock.unlock()
            return TunnelBrokerReply(state: currentState(), errorCode: .staleGeneration)
        }
        guard session.lease.appConnectionID == appConnectionID else {
            lock.unlock()
            return TunnelBrokerReply(state: currentState(), errorCode: .ownershipMismatch)
        }
        guard sameReference(reference, session.lease.reference) else {
            lock.unlock()
            return TunnelBrokerReply(state: currentState(), errorCode: .staleGeneration)
        }
        guard !session.lease.hasRouteHold else {
            lock.unlock()
            return TunnelBrokerReply(state: .routeHeld, errorCode: .routeHeld)
        }
        child = session.child
        lock.unlock()
        guard child?.stopAndReap() ?? false else {
            return TunnelBrokerReply(state: .running, errorCode: .unavailable)
        }
        lock.lock()
        defer { lock.unlock() }
        // A termination callback may already have removed this exact
        // unheld generation. Never clear a newer generation accidentally.
        if let current = active, sameReference(current.lease.reference, reference),
           !current.lease.hasRouteHold {
            if let released = current.lease.releasedRouteBindingV3 {
                retiredRouteBindingV3.record(released)
            }
            active = nil
        }
        return .init(state: .idle)
    }

    func appStatus(_ reference: TunnelReference, appConnectionID: UUID) -> TunnelBrokerReply {
        lock.lock()
        defer { lock.unlock() }
        guard reference.isValid(), let session = active,
              sameReference(reference, session.lease.reference)
        else { return TunnelBrokerReply(state: currentStateLocked(), errorCode: .staleGeneration) }
        guard session.lease.appConnectionID == appConnectionID else {
            return TunnelBrokerReply(state: currentStateLocked(), errorCode: .ownershipMismatch)
        }
        return TunnelBrokerReply(state: currentStateLocked())
    }

    func appInvalidated(appConnectionID: UUID) {
        var child: SidecarChild?
        var reference: TunnelReference?
        lock.lock()
        if var session = active, session.lease.appConnectionID == appConnectionID {
            session.lease.appConnected = false
            if !session.lease.hasRouteHold {
                child = session.child
                reference = session.lease.reference
                // Keep the exact session until stopAndReap proves absence.
                active = session
            } else {
                active = session
            }
        }
        lock.unlock()
        guard let child, let reference, child.stopAndReap() else { return }
        lock.lock()
        if let current = active, sameReference(current.lease.reference, reference),
           !current.lease.hasRouteHold, !current.lease.appConnected {
            if let released = current.lease.releasedRouteBindingV3 {
                retiredRouteBindingV3.record(released)
            }
            active = nil
        }
        lock.unlock()
    }

    func hold(_ binding: TunnelRouteBinding) -> TunnelBrokerReply {
        lock.lock()
        defer { lock.unlock() }
        guard var session = active else {
            return TunnelBrokerReply(state: .idle, errorCode: .staleGeneration)
        }
        if let error = session.lease.hold(binding) {
            return TunnelBrokerReply(state: currentStateLocked(), errorCode: error)
        }
        active = session
        return TunnelBrokerReply(state: .routeHeld)
    }

    func release(_ binding: TunnelRouteBinding) -> TunnelBrokerReply {
        var child: SidecarChild?
        var reference: TunnelReference?
        lock.lock()
        guard var session = active else {
            lock.unlock()
            return TunnelBrokerReply(state: .idle, errorCode: .staleGeneration)
        }
        if let error = session.lease.release(binding) {
            lock.unlock()
            return TunnelBrokerReply(state: currentState(), errorCode: error)
        }
        if session.lease.appConnected {
            active = session
            lock.unlock()
            return TunnelBrokerReply(state: .running)
        }
        child = session.child
        reference = session.lease.reference
        // Keep the unheld, disconnected session as a retirement tombstone
        // until the child has been positively reaped.
        active = session
        lock.unlock()
        guard child?.stopAndReap() ?? false, let reference else {
            return TunnelBrokerReply(state: .running, errorCode: .unavailable)
        }
        lock.lock()
        defer { lock.unlock() }
        if let current = active, sameReference(current.lease.reference, reference),
           !current.lease.hasRouteHold, !current.lease.appConnected {
            if let released = current.lease.releasedRouteBindingV3 {
                retiredRouteBindingV3.record(released)
            }
            active = nil
        }
        return .init(state: .idle)
    }

    func routeStatus(_ binding: TunnelRouteBinding) -> TunnelBrokerReply {
        lock.lock()
        defer { lock.unlock() }
        guard binding.isValid(), let session = active,
              sameReference(binding.reference, session.lease.reference)
        else { return TunnelBrokerReply(state: currentStateLocked(), errorCode: .staleGeneration) }
        guard session.lease.routeLeaseID == binding.routeLeaseID else {
            return TunnelBrokerReply(state: currentStateLocked(), errorCode: .holdMismatch)
        }
        return TunnelBrokerReply(state: .routeHeld)
    }

    func holdV3(_ binding: TunnelRouteBindingV3) -> TunnelBrokerRouteReplyV3 {
        lock.lock()
        defer { lock.unlock() }
        guard var session = active else {
            return TunnelBrokerRouteReplyV3(binding: binding, state: .idle, errorCode: .staleGeneration)
        }
        if let error = session.lease.holdV3(binding) {
            return TunnelBrokerRouteReplyV3(binding: binding, state: currentStateLocked(), errorCode: error)
        }
        active = session
        return TunnelBrokerRouteReplyV3(binding: binding, state: .routeHeld)
    }

    func releaseV3(_ binding: TunnelRouteBindingV3) -> TunnelBrokerRouteReplyV3 {
        var child: SidecarChild?
        var reference: TunnelReference?
        lock.lock()
        let retiredMatch = retiredRouteBindingV3.classify(binding)
        if retiredMatch == .exact {
            lock.unlock()
            return TunnelBrokerRouteReplyV3(binding: binding, state: .idle)
        }
        guard var session = active else {
            lock.unlock()
            let error: BrokerErrorCode = retiredMatch == .sameSessionMismatch ? .holdMismatch : .staleGeneration
            return TunnelBrokerRouteReplyV3(binding: binding, state: .idle, errorCode: error)
        }
        guard routeBindingV3MatchesReference(binding, session.lease.reference) else {
            let state = currentStateLocked()
            lock.unlock()
            let error: BrokerErrorCode = retiredMatch == .sameSessionMismatch ? .holdMismatch : .staleGeneration
            return TunnelBrokerRouteReplyV3(binding: binding, state: state, errorCode: error)
        }
        if let error = session.lease.releaseV3(binding) {
            lock.unlock()
            return TunnelBrokerRouteReplyV3(binding: binding, state: currentState(), errorCode: error)
        }
        if session.lease.appConnected {
            active = session
            lock.unlock()
            return TunnelBrokerRouteReplyV3(binding: binding, state: .running)
        }
        child = session.child
        reference = session.lease.reference
        active = session
        lock.unlock()
        guard child?.stopAndReap() ?? false, let reference else {
            return TunnelBrokerRouteReplyV3(binding: binding, state: .running, errorCode: .unavailable)
        }
        lock.lock()
        defer { lock.unlock() }
        if let current = active, sameReference(current.lease.reference, reference),
           !current.lease.hasRouteHold, !current.lease.appConnected {
            retiredRouteBindingV3.record(binding)
            active = nil
        }
        return TunnelBrokerRouteReplyV3(binding: binding, state: .idle)
    }

    func routeStatusV3(_ binding: TunnelRouteBindingV3) -> TunnelBrokerRouteReplyV3 {
        lock.lock()
        defer { lock.unlock() }
        let retiredMatch = retiredRouteBindingV3.classify(binding)
        if retiredMatch == .exact {
            return TunnelBrokerRouteReplyV3(binding: binding, state: .idle)
        }
        guard let session = active else {
            let error: BrokerErrorCode = retiredMatch == .sameSessionMismatch ? .holdMismatch : .staleGeneration
            return TunnelBrokerRouteReplyV3(binding: binding, state: .idle, errorCode: error)
        }
        guard routeBindingV3MatchesReference(binding, session.lease.reference) else {
            let error: BrokerErrorCode = retiredMatch == .sameSessionMismatch ? .holdMismatch : .staleGeneration
            return TunnelBrokerRouteReplyV3(binding: binding, state: currentStateLocked(), errorCode: error)
        }
        if let error = session.lease.statusV3(binding) {
            return TunnelBrokerRouteReplyV3(binding: binding, state: currentStateLocked(), errorCode: error)
        }
        return TunnelBrokerRouteReplyV3(binding: binding, state: currentStateLocked())
    }

    private func childExited(reference: TunnelReference) {
        lock.lock()
        defer { lock.unlock() }
        guard let session = active, sameReference(reference, session.lease.reference) else { return }
        // Keep a held generation as a tombstone until exact route rollback and
        // release; otherwise a new Connect could race stale private routes.
        if !session.lease.hasRouteHold {
            if let released = session.lease.releasedRouteBindingV3 {
                retiredRouteBindingV3.record(released)
            }
            active = nil
        }
    }

    private func currentState() -> BrokerState {
        lock.lock()
        defer { lock.unlock() }
        return currentStateLocked()
    }

    private func currentStateLocked() -> BrokerState {
        guard let active else { return .idle }
        return active.lease.hasRouteHold ? .routeHeld : .running
    }
}

private final class AppService: NSObject, TunnelBrokerAppProtocol {
    private let connectionID: UUID
    private let lifecycleLock = NSLock()
    private var active = true

    init(connectionID: UUID) { self.connectionID = connectionID }

    func start(reply: @escaping (TunnelSessionReply) -> Void) {
        guard lifecycleLock.withLock({ active }) else {
            reply(TunnelSessionReply(state: .idle, errorCode: .unavailable))
            return
        }
        let response = TunnelBrokerCoordinator.shared.start(appConnectionID: connectionID)
        reply(response)
        response.closeTransferredPipeCopies()
    }

    func stop(_ reference: TunnelReference, reply: @escaping (TunnelBrokerReply) -> Void) {
        guard lifecycleLock.withLock({ active }) else {
            reply(TunnelBrokerReply(state: .idle, errorCode: .unavailable))
            return
        }
        reply(TunnelBrokerCoordinator.shared.stop(reference, appConnectionID: connectionID))
    }

    func status(_ reference: TunnelReference, reply: @escaping (TunnelBrokerReply) -> Void) {
        guard lifecycleLock.withLock({ active }) else {
            reply(TunnelBrokerReply(state: .idle, errorCode: .unavailable))
            return
        }
        reply(TunnelBrokerCoordinator.shared.appStatus(reference, appConnectionID: connectionID))
    }

    func invalidate() {
        let shouldInvalidate = lifecycleLock.withLock { () -> Bool in
            guard active else { return false }
            active = false
            return true
        }
        if shouldInvalidate {
            TunnelBrokerCoordinator.shared.appInvalidated(appConnectionID: connectionID)
        }
    }
}

private final class RouteService: NSObject, TunnelBrokerRouteV3Protocol {
    func hold(_ binding: TunnelRouteBinding, reply: @escaping (TunnelBrokerReply) -> Void) {
        reply(TunnelBrokerCoordinator.shared.hold(binding))
    }

    func release(_ binding: TunnelRouteBinding, reply: @escaping (TunnelBrokerReply) -> Void) {
        reply(TunnelBrokerCoordinator.shared.release(binding))
    }

    func status(_ binding: TunnelRouteBinding, reply: @escaping (TunnelBrokerReply) -> Void) {
        reply(TunnelBrokerCoordinator.shared.routeStatus(binding))
    }

    func holdV3(_ binding: TunnelRouteBindingV3, reply: @escaping (TunnelBrokerRouteReplyV3) -> Void) {
        reply(TunnelBrokerCoordinator.shared.holdV3(binding))
    }

    func releaseV3(_ binding: TunnelRouteBindingV3, reply: @escaping (TunnelBrokerRouteReplyV3) -> Void) {
        reply(TunnelBrokerCoordinator.shared.releaseV3(binding))
    }

    func statusV3(_ binding: TunnelRouteBindingV3, reply: @escaping (TunnelBrokerRouteReplyV3) -> Void) {
        reply(TunnelBrokerCoordinator.shared.routeStatusV3(binding))
    }
}

private final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier
        guard pid > 1 else { return false }
        if connection.effectiveUserIdentifier == 0 {
            connection.setCodeSigningRequirement(routeHelperRequirement)
            let service = RouteService()
            connection.exportedInterface = routeXPCInterface()
            connection.exportedObject = service
            // Deliberately do not release a hold from XPC invalidation. The
            // route helper owns the durable rollback journal and must finish
            // rollback/fsync before sending this exact release. A broker-side
            // disconnect callback that guessed here could tear down utun
            // before private routes were removed.
            connection.resume()
            return true
        }
        let auditSession = connection.auditSessionIdentifier
        guard auditSession > AU_DEFAUDITSID, auditSession != AU_ASSIGN_ASID else { return false }
        connection.setCodeSigningRequirement(appRequirement)
        let service = AppService(connectionID: UUID())
        connection.exportedInterface = appXPCInterface()
        connection.exportedObject = service
        connection.invalidationHandler = { service.invalidate() }
        connection.interruptionHandler = { service.invalidate() }
        connection.resume()
        return true
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}

#if KYCLASH_TUNNEL_BROKER_SELF_TEST
private struct SelfTestTrustValidator: SidecarTrustValidating {
    let expectedURL: URL
    func validate(sidecarAt url: URL) -> Bool { url == expectedURL }
}

private enum SelfTestFailure: Error { case failed(String) }

private func requireSelfTest(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw SelfTestFailure.failed(message) }
}

private func runSelfTest() -> Bool {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("kyclash-tunnel-broker-self-test-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: root) }
    do {
        let resources = root.appendingPathComponent("KyClash.app/Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let broker = resources.appendingPathComponent(brokerExecutableName)
        let sidecar = resources.appendingPathComponent(sidecarExecutableName)
        try Data("broker".utf8).write(to: broker, options: [.withoutOverwriting])
        try Data("sidecar".utf8).write(to: sidecar, options: [.withoutOverwriting])
        let planner = FixedSidecarLaunchPlanner(
            trustValidator: SelfTestTrustValidator(expectedURL: sidecar)
        )
        let plan = try planner.plan(brokerExecutableURL: broker)
        try requireSelfTest(plan.executableURL == sidecar, "planner must derive the fixed sibling sidecar")
        try requireSelfTest(plan.arguments.isEmpty, "planner argv must be fixed empty")
        try requireSelfTest(plan.environment.isEmpty, "planner environment must be fixed empty")

        let wrongBroker = resources.appendingPathComponent("caller-selected")
        try Data("wrong".utf8).write(to: wrongBroker, options: [.withoutOverwriting])
        do {
            _ = try planner.plan(brokerExecutableURL: wrongBroker)
            throw SelfTestFailure.failed("caller-selected broker layout must fail")
        } catch LaunchPlanError.invalidBrokerLayout {}

        try FileManager.default.removeItem(at: sidecar)
        try FileManager.default.createSymbolicLink(
            at: sidecar,
            withDestinationURL: resources.appendingPathComponent("missing-sidecar")
        )
        do {
            _ = try planner.plan(brokerExecutableURL: broker)
            throw SelfTestFailure.failed("symlinked sidecar must fail")
        } catch LaunchPlanError.invalidSidecar {}

        let connectionID = UUID()
        let reference = TunnelReference(generation: 7, sidecarInstanceID: "instance-00000007")
        let stale = TunnelReference(generation: 6, sidecarInstanceID: "instance-00000006")
        let binding = TunnelRouteBinding(reference: reference, routeLeaseID: "route-lease-0007")
        let wrongBinding = TunnelRouteBinding(reference: reference, routeLeaseID: "route-lease-9999")
        var lease = SessionLeaseState(reference: reference, appConnectionID: connectionID)
        try requireSelfTest(reference.isValid() && binding.isValid(), "valid typed references must pass")
        try requireSelfTest(lease.hold(binding) == nil, "exact first hold must pass")
        try requireSelfTest(lease.hold(binding) == nil, "duplicate exact hold must be idempotent")
        lease.appConnected = false
        try requireSelfTest(lease.routeLeaseID != nil, "App loss must retain the route hold")
        try requireSelfTest(lease.release(wrongBinding) == .holdMismatch, "wrong lease must not release")
        try requireSelfTest(
            lease.release(TunnelRouteBinding(reference: stale, routeLeaseID: binding.routeLeaseID))
                == .staleGeneration,
            "stale generation must not release"
        )
        try requireSelfTest(lease.release(binding) == nil, "exact release must pass")
        try requireSelfTest(!lease.appConnected && lease.routeLeaseID == nil,
                            "exact release after App loss must become retireable")

        let bindingV3 = TunnelRouteBindingV3(
            brokerGeneration: reference.generation,
            sidecarInstanceID: reference.sidecarInstanceID,
            routeLeaseID: "route-lease-v3-0007",
            operationID: "operation-v3-0007"
        )
        let wrongOperationV3 = TunnelRouteBindingV3(
            brokerGeneration: reference.generation,
            sidecarInstanceID: reference.sidecarInstanceID,
            routeLeaseID: bindingV3.routeLeaseID,
            operationID: "operation-v3-9999"
        )
        let staleV3 = TunnelRouteBindingV3(
            brokerGeneration: stale.generation,
            sidecarInstanceID: stale.sidecarInstanceID,
            routeLeaseID: bindingV3.routeLeaseID,
            operationID: bindingV3.operationID
        )
        try requireSelfTest(
            lease.holdV3(bindingV3) == .holdMismatch,
            "released legacy lease must never upgrade into a v3 authority"
        )
        var leaseV3 = SessionLeaseState(reference: reference, appConnectionID: connectionID)
        try requireSelfTest(bindingV3.isValid(), "valid v3 binding must pass")
        try requireSelfTest(leaseV3.holdV3(bindingV3) == nil, "exact v3 hold must pass")
        try requireSelfTest(leaseV3.holdV3(bindingV3) == nil, "duplicate exact v3 hold must be idempotent")
        try requireSelfTest(leaseV3.statusV3(bindingV3) == nil, "exact v3 status must pass")
        try requireSelfTest(
            leaseV3.hold(binding) == .holdMismatch,
            "legacy hold must not mix with an active v3 tuple"
        )
        try requireSelfTest(
            leaseV3.statusV3(wrongOperationV3) == .holdMismatch,
            "wrong v3 operation must fail closed"
        )
        try requireSelfTest(
            leaseV3.releaseV3(staleV3) == .staleGeneration,
            "stale v3 generation must not release"
        )
        try requireSelfTest(
            leaseV3.releaseV3(wrongOperationV3) == .holdMismatch,
            "wrong v3 operation must not release"
        )
        try requireSelfTest(leaseV3.releaseV3(bindingV3) == nil, "exact v3 release must pass")
        try requireSelfTest(
            leaseV3.releaseV3(bindingV3) == nil,
            "duplicate exact v3 release must be idempotent"
        )
        try requireSelfTest(!leaseV3.hasRouteHold, "released v3 tuple must not retain a hold")
        try requireSelfTest(
            leaseV3.hold(binding) == .holdMismatch,
            "released v3 tuple must never downgrade into a legacy authority"
        )
        try requireSelfTest(
            leaseV3.holdV3(bindingV3) == .holdMismatch,
            "released v3 tuple must not replay into a new hold"
        )
        var noHoldLeaseV3 = SessionLeaseState(reference: reference, appConnectionID: connectionID)
        try requireSelfTest(
            noHoldLeaseV3.releaseV3(bindingV3) == nil,
            "exact current session without a hold must accept a bounded no-op release"
        )
        try requireSelfTest(
            noHoldLeaseV3.statusV3(bindingV3) == nil,
            "no-op release must retain exact absence proof"
        )
        try requireSelfTest(
            noHoldLeaseV3.releaseV3(wrongOperationV3) == .holdMismatch,
            "no-op release must not authorize another operation"
        )
        var retiredV3 = RetiredRouteBindingV3Tombstone()
        retiredV3.record(bindingV3)
        try requireSelfTest(
            retiredV3.classify(bindingV3) == .exact,
            "lost exact release reply must be recoverable from the tombstone"
        )
        try requireSelfTest(
            retiredV3.classify(wrongOperationV3) == .sameSessionMismatch,
            "same-session wrong operation must remain a mismatch"
        )
        let newerV3 = TunnelRouteBindingV3(
            brokerGeneration: reference.generation + 1,
            sidecarInstanceID: "instance-00000008",
            routeLeaseID: bindingV3.routeLeaseID,
            operationID: bindingV3.operationID
        )
        try requireSelfTest(
            retiredV3.classify(newerV3) == .unrelated,
            "retired tuple must not affect a newer generation"
        )
        let replyV3 = TunnelBrokerRouteReplyV3(binding: bindingV3, state: .routeHeld)
        try requireSelfTest(
            replyV3.protocolVersion == routeHelperV3ProtocolVersion
                && replyV3.brokerProtocolVersion == routeBrokerProtocolVersion
                && replyV3.brokerGeneration == bindingV3.brokerGeneration
                && replyV3.sidecarInstanceID == bindingV3.sidecarInstanceID
                && replyV3.routeLeaseID == bindingV3.routeLeaseID
                && replyV3.operationID == bindingV3.operationID,
            "v3 reply must echo the complete exact tuple"
        )
        let bindingV3Archive = try NSKeyedArchiver.archivedData(
            withRootObject: bindingV3,
            requiringSecureCoding: true
        )
        let decodedBindingV3 = try NSKeyedUnarchiver.unarchivedObject(
            ofClass: TunnelRouteBindingV3.self,
            from: bindingV3Archive
        )
        try requireSelfTest(
            decodedBindingV3.map { sameRouteBindingV3($0, bindingV3) } == true,
            "v3 binding secure archive must preserve the complete tuple"
        )
        let replyV3Archive = try NSKeyedArchiver.archivedData(
            withRootObject: replyV3,
            requiringSecureCoding: true
        )
        let decodedReplyV3 = try NSKeyedUnarchiver.unarchivedObject(
            ofClass: TunnelBrokerRouteReplyV3.self,
            from: replyV3Archive
        )
        try requireSelfTest(
            decodedReplyV3?.brokerGeneration == bindingV3.brokerGeneration
                && decodedReplyV3?.operationID == bindingV3.operationID,
            "v3 reply secure archive must preserve its exact echo"
        )

        // The XPC reply duplicates both descriptors for the App.  Once the
        // reply block returns, only those duplicated descriptors may remain;
        // the broker's local copies must be closed so EOF/cleanup is not
        // masked by an accidental extra writer or reader.
        let transferPipe = Pipe()
        let transferredReply = TunnelSessionReply(
            state: .running,
            reference: reference,
            inputHandle: transferPipe.fileHandleForWriting,
            outputHandle: transferPipe.fileHandleForReading
        )
        let transferredInput = transferredReply.inputHandle!
        let transferredOutput = transferredReply.outputHandle!
        let transferredInputFD = transferredInput.fileDescriptor
        let transferredOutputFD = transferredOutput.fileDescriptor
        transferredReply.closeTransferredPipeCopies()
        try requireSelfTest(
            descriptorIsClosed(transferredInputFD) && descriptorIsClosed(transferredOutputFD),
            "broker pipe copies must close after the XPC reply"
        )

        let invalidGeneration = TunnelReference(generation: 0, sidecarInstanceID: "instance-00000000")
        let invalidID = TunnelReference(generation: 1, sidecarInstanceID: "bad/id")
        let legacyShapedV3 = TunnelRouteBindingV3(
            protocolVersion: 2,
            brokerGeneration: reference.generation,
            sidecarInstanceID: reference.sidecarInstanceID,
            routeLeaseID: bindingV3.routeLeaseID,
            operationID: bindingV3.operationID
        )
        try requireSelfTest(!invalidGeneration.isValid(), "zero generation must fail")
        try requireSelfTest(!invalidID.isValid(), "invalid instance ID must fail")
        try requireSelfTest(!legacyShapedV3.isValid(), "v2 input must remain recovery-only")
        print("tunnel_broker_self_test_ok")
        return true
    } catch {
        fputs("tunnel_broker_self_test_failed: \(error)\n", stderr)
        return false
    }
}

private func descriptorIsClosed(_ descriptor: Int32) -> Bool {
    guard descriptor >= 0 else { return true }
    return fcntl(descriptor, F_GETFD) == -1 && errno == EBADF
}
#endif

@main
private enum TunnelBrokerMain {
    static func main() {
        #if KYCLASH_TUNNEL_BROKER_SELF_TEST
        if CommandLine.arguments.contains("--self-test") {
            if !runSelfTest() { exit(1) }
            return
        }
        #endif
        let delegate = ListenerDelegate()
        let listener = NSXPCListener(machServiceName: brokerMachService)
        listener.delegate = delegate
        listener.resume()
        RunLoop.current.run()
    }
}
