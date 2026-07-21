import Foundation
import ServiceManagement

@main
enum LabRegistration {
    static func main() {
        let service = SMAppService.daemon(plistName: "net.kysion.kyclash.route-helper.plist")
        do {
            if CommandLine.arguments.dropFirst().contains("unregister") {
                try service.unregister()
                print("unregistered:\(service.status.rawValue)")
                return
            }
            try service.register()
            print("registered:\(service.status.rawValue)")
        } catch {
            fputs("registration_failed:\(error)\n", stderr)
            exit(1)
        }
    }
}
