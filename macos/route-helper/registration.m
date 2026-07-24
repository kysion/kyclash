#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Security.h>
#import <sys/stat.h>

static NSString *const KyClashRouteHelperPlist = @"net.kysion.kyclash.route-helper.plist";
static NSString *const KyClashTunnelBrokerPlist = @"net.kysion.kyclash.tunnel-broker.plist";

static SMAppService *KyClashRouteHelperService(void) {
  return [SMAppService daemonServiceWithPlistName:KyClashRouteHelperPlist];
}

static SMAppService *KyClashTunnelBrokerService(void) {
  return [SMAppService daemonServiceWithPlistName:KyClashTunnelBrokerPlist];
}

int32_t kyclash_route_helper_status(void) {
  return (int32_t)KyClashRouteHelperService().status;
}

int32_t kyclash_route_helper_register(void) {
  NSError *error = nil;
  if ([KyClashRouteHelperService() registerAndReturnError:&error]) {
    return 0;
  }
  return error == nil ? -1 : (int32_t)error.code;
}

int32_t kyclash_route_helper_unregister(void) {
  NSError *error = nil;
  if ([KyClashRouteHelperService() unregisterAndReturnError:&error]) {
    return 0;
  }
  return error == nil ? -1 : (int32_t)error.code;
}

void kyclash_route_helper_open_settings(void) {
  [SMAppService openSystemSettingsLoginItems];
}

int32_t kyclash_tunnel_broker_status(void) {
  return (int32_t)KyClashTunnelBrokerService().status;
}

int32_t kyclash_tunnel_broker_register(void) {
  NSError *error = nil;
  if ([KyClashTunnelBrokerService() registerAndReturnError:&error]) {
    return 0;
  }
  return error == nil ? -1 : (int32_t)error.code;
}

int32_t kyclash_tunnel_broker_unregister(void) {
  NSError *error = nil;
  if ([KyClashTunnelBrokerService() unregisterAndReturnError:&error]) {
    return 0;
  }
  return error == nil ? -1 : (int32_t)error.code;
}

// Connect is allowed to cross the privileged boundary only when the exact
// bundled helper/broker executables and their launchd manifests are present
// and satisfy KyClash's fixed Developer ID requirements. This check is
// deliberately independent of SMAppService.status: an Enabled service with a
// replaced binary or plist must fail closed before any XPC/sidecar start.
static BOOL KyClashRegularNonSymlink(NSString *path) {
  struct stat info;
  return path != nil && lstat(path.fileSystemRepresentation, &info) == 0 &&
         (info.st_mode & S_IFMT) == S_IFREG && info.st_nlink == 1;
}

static BOOL KyClashCodeMatches(NSString *path, NSString *identifier) {
  if (!KyClashRegularNonSymlink(path))
    return NO;
  SecStaticCodeRef code = NULL;
  SecRequirementRef requirement = NULL;
  NSString *requirementText = [NSString stringWithFormat:
      @"anchor apple generic and identifier \"%@\" and certificate leaf[subject.OU] = \"RQUQ8Y3S9H\"",
      identifier];
  BOOL valid = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],
                                            kSecCSDefaultFlags, &code) == errSecSuccess &&
               SecRequirementCreateWithString((__bridge CFStringRef)requirementText,
                                                kSecCSDefaultFlags, &requirement) == errSecSuccess &&
               SecStaticCodeCheckValidity(code, kSecCSStrictValidate, requirement) == errSecSuccess;
  if (requirement != NULL)
    CFRelease(requirement);
  if (code != NULL)
    CFRelease(code);
  return valid;
}

static BOOL KyClashManifestMatches(NSString *bundlePath, NSString *plistName,
                                    NSString *label, NSString *machService,
                                    NSString *program) {
  NSString *path = [bundlePath stringByAppendingPathComponent:
      [NSString stringWithFormat:@"Contents/Library/LaunchDaemons/%@", plistName]];
  NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:path];
  NSDictionary *services = [manifest objectForKey:@"MachServices"];
  return [manifest[@"Label"] isEqualToString:label] &&
         [manifest[@"BundleProgram"] isEqualToString:program] &&
         [services[machService] boolValue] && services.count == 1;
}

int32_t kyclash_privileged_networking_verify_bundled_requirements(void) {
  NSBundle *bundle = [NSBundle mainBundle];
  NSString *bundlePath = bundle.bundlePath;
  NSString *helper = [bundle pathForResource:@"kyclash-route-helper" ofType:nil];
  NSString *broker = [bundle pathForResource:@"kyclash-tunnel-broker" ofType:nil];
  if (helper == nil)
    helper = [bundlePath stringByAppendingPathComponent:@"Contents/Resources/kyclash-route-helper"];
  if (broker == nil)
    broker = [bundlePath stringByAppendingPathComponent:@"Contents/Resources/kyclash-tunnel-broker"];
  BOOL executables = KyClashCodeMatches(helper, @"net.kysion.kyclash.route-helper") &&
                     KyClashCodeMatches(broker, @"net.kysion.kyclash.tunnel-broker");
  BOOL manifests = KyClashManifestMatches(
      bundlePath, KyClashRouteHelperPlist, @"net.kysion.kyclash.route-helper",
      @"net.kysion.kyclash.route-helper", @"Contents/Resources/kyclash-route-helper") &&
                   KyClashManifestMatches(
      bundlePath, KyClashTunnelBrokerPlist, @"net.kysion.kyclash.tunnel-broker",
      @"net.kysion.kyclash.tunnel-broker", @"Contents/Resources/kyclash-tunnel-broker");
  return executables && manifests ? 0 : -1;
}
