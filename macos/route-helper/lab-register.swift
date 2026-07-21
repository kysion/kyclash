import Foundation
import ServiceManagement

@main
enum LabRegistration {
    static func main() {
        let service = SMAppService.daemon(plistName: "net.kysion.kyclash.route-helper.plist")
        do {
            try service.register()
            print("registered:\(service.status.rawValue)")
        } catch {
            fputs("registration_failed:\(error)\n", stderr)
            exit(1)
        }
    }
}
