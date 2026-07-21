#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

static NSString *const KyClashRouteHelperPlist = @"net.kysion.kyclash.route-helper.plist";

static SMAppService *KyClashRouteHelperService(void) {
  return [SMAppService daemonServiceWithPlistName:KyClashRouteHelperPlist];
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
