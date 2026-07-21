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

private final class RouteHelperService: NSObject, RouteHelperProtocol {
    private var owner: LeaseOwner?

    func discover(reply: @escaping (HelperReply) -> Void) { reply(HelperReply(state: "idle")) }

    func begin(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void) {
        guard owner.isValid(), self.owner == nil else {
            reply(HelperReply(state: "failed_closed", errorCode: "invalid_owner")); return
        }
        self.owner = owner
        reply(HelperReply(state: "prepared", errorCode: "not_ready"))
    }

    func apply(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(valid(reference) ? HelperReply(state: "prepared", errorCode: "not_ready") : invalidReply())
    }

    func rollback(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        guard valid(reference) else { reply(invalidReply()); return }
        owner = nil
        reply(HelperReply(state: "idle"))
    }

    func recover(_ owner: LeaseOwner, reply: @escaping (HelperReply) -> Void) {
        reply(HelperReply(state: "failed_closed", errorCode: owner.isValid() ? "not_ready" : "invalid_owner"))
    }

    func heartbeat(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(valid(reference) ? HelperReply(state: "prepared") : invalidReply())
    }

    func status(_ reference: LeaseReference, reply: @escaping (HelperReply) -> Void) {
        reply(valid(reference) ? HelperReply(state: "prepared") : invalidReply())
    }

    private func valid(_ reference: LeaseReference) -> Bool {
        reference.isValid() && reference.leaseID == owner?.reference.leaseID
            && reference.operationID == owner?.reference.operationID
    }

    private func invalidReply() -> HelperReply {
        HelperReply(state: "failed_closed", errorCode: "ownership_mismatch")
    }
}

private final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier != 0 else { return false }
        connection.setCodeSigningRequirement(appRequirement)
        connection.exportedInterface = routeHelperInterface()
        connection.exportedObject = RouteHelperService()
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

@main
private enum RouteHelperMain {
    static func main() {
        let delegate = ListenerDelegate()
        let listener = NSXPCListener(machServiceName: "net.kysion.kyclash.route-helper")
        listener.delegate = delegate
        listener.resume()
        RunLoop.current.run()
    }
}
