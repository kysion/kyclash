#import <Foundation/Foundation.h>
#include <stdint.h>

static NSString *const KCRMachService = @"net.kysion.kyclash.route-helper";
static const int64_t KCRTimeoutNanoseconds = 5LL * NSEC_PER_SEC;
static const uint8_t KCRProtocolVersion = 2;

typedef struct {
  int32_t transport_status;
  int32_t protocol_version;
  int32_t state;
  int32_t error_code;
} KCRClientReply;

static const uintptr_t KCRMaximumMihomoInterfaces = 1;
static const uint64_t KCRMaximumSignedRevision = UINT64_C(0x7fffffffffffffff);

@interface KCRLeaseReference : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t version;
@property(nonatomic, copy, readonly) NSString *leaseID;
@property(nonatomic, copy, readonly) NSString *operationID;
- (instancetype)initWithVersion:(uint8_t)version
                        leaseID:(NSString *)leaseID
                    operationID:(NSString *)operationID;
@end

@implementation KCRLeaseReference
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithVersion:(uint8_t)version
                        leaseID:(NSString *)leaseID
                    operationID:(NSString *)operationID {
  if (leaseID == nil || operationID == nil)
    return nil;
  if ((self = [super init])) {
    _version = version;
    _leaseID = [leaseID copy];
    _operationID = [operationID copy];
  }
  return self;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  NSInteger rawVersion = [coder decodeIntegerForKey:@"version"];
  NSString *leaseID =
      [coder decodeObjectOfClass:NSString.class forKey:@"leaseID"];
  NSString *operationID =
      [coder decodeObjectOfClass:NSString.class forKey:@"operationID"];
  if (rawVersion < 0 || rawVersion > UINT8_MAX || leaseID == nil ||
      operationID == nil)
    return nil;
  return [self initWithVersion:(uint8_t)rawVersion
                       leaseID:leaseID
                   operationID:operationID];
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_version forKey:@"version"];
  [coder encodeObject:_leaseID forKey:@"leaseID"];
  [coder encodeObject:_operationID forKey:@"operationID"];
}
@end

@interface KCRLeaseOwner : NSObject <NSSecureCoding>
@property(nonatomic, readonly) KCRLeaseReference *reference;
@property(nonatomic, copy, readonly) NSString *sidecarInstanceID;
@property(nonatomic, copy, readonly) NSString *interfaceName;
@property(nonatomic, copy, readonly) NSString *tunnelOperationID;
@property(nonatomic, readonly) uint16_t mtu;
@property(nonatomic, readonly) BOOL hasIPv4;
@property(nonatomic, readonly) BOOL hasIPv6;
@property(nonatomic, readonly) uint64_t profileRevision;
@property(nonatomic, copy, readonly)
    NSArray<NSString *> *activeMihomoTunInterfaces;
@property(nonatomic, copy, readonly) NSArray<NSString *> *privateCIDRs;
- (instancetype)initWithReference:(KCRLeaseReference *)reference
                sidecarInstanceID:(NSString *)sidecarInstanceID
                    interfaceName:(NSString *)interfaceName
                tunnelOperationID:(NSString *)tunnelOperationID
                              mtu:(uint16_t)mtu
                          hasIPv4:(BOOL)hasIPv4
                          hasIPv6:(BOOL)hasIPv6
                  profileRevision:(uint64_t)profileRevision
        activeMihomoTunInterfaces:
            (NSArray<NSString *> *)activeMihomoTunInterfaces
                     privateCIDRs:(NSArray<NSString *> *)privateCIDRs;
@end

@implementation KCRLeaseOwner
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithReference:(KCRLeaseReference *)reference
                sidecarInstanceID:(NSString *)sidecarInstanceID
                    interfaceName:(NSString *)interfaceName
                tunnelOperationID:(NSString *)tunnelOperationID
                              mtu:(uint16_t)mtu
                          hasIPv4:(BOOL)hasIPv4
                          hasIPv6:(BOOL)hasIPv6
                  profileRevision:(uint64_t)profileRevision
        activeMihomoTunInterfaces:
            (NSArray<NSString *> *)activeMihomoTunInterfaces
                     privateCIDRs:(NSArray<NSString *> *)privateCIDRs {
  if (reference == nil || sidecarInstanceID == nil || interfaceName == nil ||
      tunnelOperationID == nil || activeMihomoTunInterfaces == nil ||
      privateCIDRs == nil || profileRevision == 0 ||
      profileRevision > KCRMaximumSignedRevision ||
      activeMihomoTunInterfaces.count > KCRMaximumMihomoInterfaces)
    return nil;
  if ((self = [super init])) {
    _reference = reference;
    _sidecarInstanceID = [sidecarInstanceID copy];
    _interfaceName = [interfaceName copy];
    _tunnelOperationID = [tunnelOperationID copy];
    _mtu = mtu;
    _hasIPv4 = hasIPv4;
    _hasIPv6 = hasIPv6;
    _profileRevision = profileRevision;
    _activeMihomoTunInterfaces = [activeMihomoTunInterfaces copy];
    _privateCIDRs = [privateCIDRs copy];
  }
  return self;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  NSSet *cidrClasses =
      [NSSet setWithObjects:NSArray.class, NSString.class, nil];
  if (![coder containsValueForKey:@"mtu"] ||
      ![coder containsValueForKey:@"profileRevision"] ||
      ![coder containsValueForKey:@"hasIPv4"] ||
      ![coder containsValueForKey:@"hasIPv6"])
    return nil;
  NSInteger rawMtu = [coder decodeIntegerForKey:@"mtu"];
  int64_t rawRevision = [coder decodeInt64ForKey:@"profileRevision"];
  NSInteger rawHasIPv4 = [coder decodeIntegerForKey:@"hasIPv4"];
  NSInteger rawHasIPv6 = [coder decodeIntegerForKey:@"hasIPv6"];
  NSArray<NSString *> *activeMihomoTunInterfaces =
      [coder decodeObjectOfClasses:cidrClasses
                            forKey:@"activeMihomoTunInterfaces"];
  NSArray<NSString *> *privateCIDRs =
      [coder decodeObjectOfClasses:cidrClasses forKey:@"privateCIDRs"];
  if (rawMtu < 0 || rawMtu > UINT16_MAX || rawRevision <= 0 || rawHasIPv4 < 0 ||
      rawHasIPv4 > 1 || rawHasIPv6 < 0 || rawHasIPv6 > 1 ||
      activeMihomoTunInterfaces == nil || privateCIDRs == nil)
    return nil;
  return [self
              initWithReference:[coder
                                    decodeObjectOfClass:KCRLeaseReference.class
                                                 forKey:@"reference"]
              sidecarInstanceID:[coder decodeObjectOfClass:NSString.class
                                                    forKey:@"sidecarInstanceID"]
                  interfaceName:[coder decodeObjectOfClass:NSString.class
                                                    forKey:@"interfaceName"]
              tunnelOperationID:[coder decodeObjectOfClass:NSString.class
                                                    forKey:@"tunnelOperationID"]
                            mtu:(uint16_t)rawMtu
                        hasIPv4:(BOOL)rawHasIPv4
                        hasIPv6:(BOOL)rawHasIPv6
                profileRevision:(uint64_t)rawRevision
      activeMihomoTunInterfaces:activeMihomoTunInterfaces
                   privateCIDRs:privateCIDRs];
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:_reference forKey:@"reference"];
  [coder encodeObject:_sidecarInstanceID forKey:@"sidecarInstanceID"];
  [coder encodeObject:_interfaceName forKey:@"interfaceName"];
  [coder encodeObject:_tunnelOperationID forKey:@"tunnelOperationID"];
  [coder encodeInteger:_mtu forKey:@"mtu"];
  // Swift decodes these fields as bounded integers.  Encoding as BOOL stores
  // an incompatible keyed-archive primitive (decodeInteger returns zero),
  // which would silently make every dual-stack owner invalid at the XPC
  // boundary.
  [coder encodeInteger:_hasIPv4 ? 1 : 0 forKey:@"hasIPv4"];
  [coder encodeInteger:_hasIPv6 ? 1 : 0 forKey:@"hasIPv6"];
  [coder encodeInt64:(int64_t)_profileRevision forKey:@"profileRevision"];
  [coder encodeObject:_activeMihomoTunInterfaces
               forKey:@"activeMihomoTunInterfaces"];
  [coder encodeObject:_privateCIDRs forKey:@"privateCIDRs"];
}
@end

@interface KCRReply : NSObject <NSSecureCoding>
@property(nonatomic, readonly) int32_t protocolVersion;
@property(nonatomic, copy, readonly) NSString *state;
@property(nonatomic, copy, readonly, nullable) NSString *errorCode;
@end

@implementation KCRReply
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"])
    return nil;
  NSInteger rawProtocolVersion = [coder decodeIntegerForKey:@"protocolVersion"];
  if (rawProtocolVersion < 0 || rawProtocolVersion > INT32_MAX)
    return nil;
  self = [super init];
  if (self == nil)
    return nil;
  _protocolVersion = (int32_t)rawProtocolVersion;
  _state = [[coder decodeObjectOfClass:NSString.class forKey:@"state"] copy];
  _errorCode =
      [[coder decodeObjectOfClass:NSString.class forKey:@"errorCode"] copy];
  return _state == nil ? nil : self;
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_protocolVersion forKey:@"protocolVersion"];
  [coder encodeObject:_state forKey:@"state"];
  [coder encodeObject:_errorCode forKey:@"errorCode"];
}
@end

@protocol KCRRouteHelperProtocol
- (void)discoverWithReply:(void (^)(KCRReply *))reply;
- (void)begin:(KCRLeaseOwner *)owner reply:(void (^)(KCRReply *))reply;
- (void)apply:(KCRLeaseReference *)reference reply:(void (^)(KCRReply *))reply;
- (void)rollback:(KCRLeaseReference *)reference
           reply:(void (^)(KCRReply *))reply;
- (void)recover:(KCRLeaseOwner *)owner reply:(void (^)(KCRReply *))reply;
- (void)heartbeat:(KCRLeaseReference *)reference
            reply:(void (^)(KCRReply *))reply;
- (void)status:(KCRLeaseReference *)reference reply:(void (^)(KCRReply *))reply;
@end

@interface KCRClient : NSObject
@property(nonatomic, readonly) NSXPCConnection *connection;
@end

static NSXPCInterface *KCRClientInterface(void) {
  NSXPCInterface *interface =
      [NSXPCInterface interfaceWithProtocol:@protocol(KCRRouteHelperProtocol)];
  NSSet *reply = [NSSet setWithObject:KCRReply.class];
  NSSet *owner =
      [NSSet setWithObjects:KCRLeaseOwner.class, KCRLeaseReference.class,
                            NSArray.class, NSString.class, nil];
  NSSet *reference =
      [NSSet setWithObjects:KCRLeaseReference.class, NSString.class, nil];
  [interface setClasses:reply
            forSelector:@selector(discoverWithReply:)
          argumentIndex:0
                ofReply:YES];
  for (NSString *selectorName in @[ @"begin:reply:", @"recover:reply:" ]) {
    SEL selector = NSSelectorFromString(selectorName);
    [interface setClasses:owner
              forSelector:selector
            argumentIndex:0
                  ofReply:NO];
    [interface setClasses:reply
              forSelector:selector
            argumentIndex:0
                  ofReply:YES];
  }
  for (NSString *selectorName in @[
         @"apply:reply:", @"rollback:reply:", @"heartbeat:reply:",
         @"status:reply:"
       ]) {
    SEL selector = NSSelectorFromString(selectorName);
    [interface setClasses:reference
              forSelector:selector
            argumentIndex:0
                  ofReply:NO];
    [interface setClasses:reply
              forSelector:selector
            argumentIndex:0
                  ofReply:YES];
  }
  return interface;
}

@implementation KCRClient
- (instancetype)init {
  if ((self = [super init])) {
    _connection = [[NSXPCConnection alloc]
        initWithMachServiceName:KCRMachService
                        options:NSXPCConnectionPrivileged];
    _connection.remoteObjectInterface = KCRClientInterface();
    [_connection resume];
  }
  return self;
}
- (void)dealloc {
  [_connection invalidate];
}
@end

static int32_t KCRStateCode(NSString *state) {
  if ([state isEqualToString:@"idle"])
    return 0;
  if ([state isEqualToString:@"prepared"])
    return 1;
  if ([state isEqualToString:@"applied"])
    return 2;
  if ([state isEqualToString:@"rolling_back"])
    return 3;
  if ([state isEqualToString:@"failed_closed"])
    return 4;
  return -1;
}

static int32_t KCRErrorCode(NSString *error) {
  if (error == nil)
    return 0;
  if ([error isEqualToString:@"not_ready"])
    return 1;
  if ([error isEqualToString:@"invalid_owner"])
    return 2;
  if ([error isEqualToString:@"ownership_mismatch"])
    return 3;
  if ([error isEqualToString:@"journal_write_failed"])
    return 4;
  if ([error isEqualToString:@"route_apply_failed"])
    return 5;
  if ([error isEqualToString:@"rollback_failed"])
    return 6;
  if ([error isEqualToString:@"recovery_required"])
    return 7;
  if ([error isEqualToString:@"journal_corrupt"])
    return 8;
  if ([error isEqualToString:@"route_conflict"])
    return 9;
  return -1;
}

static KCRClientReply KCRFailure(void) {
  return (KCRClientReply){.transport_status = -1,
                          .protocol_version = -1,
                          .state = -1,
                          .error_code = -1};
}

static KCRClientReply KCRWait(KCRClient *client,
                              void (^invoke)(id<KCRRouteHelperProtocol>,
                                             void (^)(KCRReply *))) {
  if (client == nil)
    return KCRFailure();
  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
  __block KCRClientReply result = KCRFailure();
  id<KCRRouteHelperProtocol> proxy = [client.connection
      remoteObjectProxyWithErrorHandler:^(__unused NSError *error) {
        dispatch_semaphore_signal(semaphore);
      }];
  invoke(proxy, ^(KCRReply *reply) {
    if (reply == nil) {
      dispatch_semaphore_signal(semaphore);
      return;
    }
    result = (KCRClientReply){.transport_status = 0,
                              .protocol_version = reply.protocolVersion,
                              .state = KCRStateCode(reply.state),
                              .error_code = KCRErrorCode(reply.errorCode)};
    dispatch_semaphore_signal(semaphore);
  });
  if (dispatch_semaphore_wait(
          semaphore, dispatch_time(DISPATCH_TIME_NOW, KCRTimeoutNanoseconds)) !=
      0) {
    return KCRFailure();
  }
  return result;
}

void *kyclash_route_helper_client_create(void) {
  return (__bridge_retained void *)[[KCRClient alloc] init];
}

void kyclash_route_helper_client_destroy(void *raw) {
  if (raw != NULL)
    CFBridgingRelease(raw);
}

KCRClientReply kyclash_route_helper_client_discover(void *raw) {
  KCRClient *client = (__bridge KCRClient *)raw;
  return KCRWait(
      client, ^(id<KCRRouteHelperProtocol> proxy, void (^reply)(KCRReply *)) {
        [proxy discoverWithReply:reply];
      });
}

static KCRLeaseReference *KCRReference(uint8_t version, const char *lease,
                                       const char *operation) {
  if (version != KCRProtocolVersion || lease == NULL || operation == NULL)
    return nil;
  NSString *leaseID = [NSString stringWithUTF8String:lease];
  NSString *operationID = [NSString stringWithUTF8String:operation];
  if (leaseID == nil || operationID == nil)
    return nil;
  return [[KCRLeaseReference alloc] initWithVersion:version
                                            leaseID:leaseID
                                        operationID:operationID];
}

KCRClientReply kyclash_route_helper_client_owner(
    void *raw, int32_t method, uint8_t version, const char *lease,
    const char *operation, const char *instance, const char *interface_name,
    const char *tunnel_operation, uint16_t mtu, uint64_t revision,
    uint8_t has_ipv4, uint8_t has_ipv6, const char *const *mihomo_interfaces,
    uintptr_t mihomo_count, const char *const *cidrs, uintptr_t cidr_count) {
  if (raw == NULL || method < 0 || method > 1 || instance == NULL ||
      interface_name == NULL || tunnel_operation == NULL || revision == 0 ||
      revision > KCRMaximumSignedRevision || has_ipv4 > 1 || has_ipv6 > 1 ||
      mihomo_count > KCRMaximumMihomoInterfaces ||
      (mihomo_count > 0 && mihomo_interfaces == NULL) || cidrs == NULL ||
      cidr_count == 0 || cidr_count > 64)
    return KCRFailure();
  KCRLeaseReference *reference = KCRReference(version, lease, operation);
  NSString *instanceID = [NSString stringWithUTF8String:instance];
  NSString *interfaceID = [NSString stringWithUTF8String:interface_name];
  NSString *tunnelOperationID =
      [NSString stringWithUTF8String:tunnel_operation];
  if (reference == nil || instanceID == nil || interfaceID == nil ||
      tunnelOperationID == nil)
    return KCRFailure();
  NSMutableArray<NSString *> *mihomoValues =
      [NSMutableArray arrayWithCapacity:mihomo_count];
  for (uintptr_t index = 0; index < mihomo_count; index++) {
    if (mihomo_interfaces[index] == NULL)
      return KCRFailure();
    NSString *value = [NSString stringWithUTF8String:mihomo_interfaces[index]];
    if (value == nil)
      return KCRFailure();
    [mihomoValues addObject:value];
  }
  NSMutableArray<NSString *> *values =
      [NSMutableArray arrayWithCapacity:cidr_count];
  for (uintptr_t index = 0; index < cidr_count; index++) {
    if (cidrs[index] == NULL)
      return KCRFailure();
    NSString *value = [NSString stringWithUTF8String:cidrs[index]];
    if (value == nil)
      return KCRFailure();
    [values addObject:value];
  }
  KCRLeaseOwner *owner =
      [[KCRLeaseOwner alloc] initWithReference:reference
                             sidecarInstanceID:instanceID
                                 interfaceName:interfaceID
                             tunnelOperationID:tunnelOperationID
                                           mtu:mtu
                                       hasIPv4:(BOOL)has_ipv4
                                       hasIPv6:(BOOL)has_ipv6
                               profileRevision:revision
                     activeMihomoTunInterfaces:mihomoValues
                                  privateCIDRs:values];
  if (owner == nil)
    return KCRFailure();
  KCRClient *client = (__bridge KCRClient *)raw;
  return KCRWait(
      client, ^(id<KCRRouteHelperProtocol> proxy, void (^reply)(KCRReply *)) {
        if (method == 0) {
          [proxy begin:owner reply:reply];
        } else {
          [proxy recover:owner reply:reply];
        }
      });
}

KCRClientReply kyclash_route_helper_client_reference(void *raw, int32_t method,
                                                     uint8_t version,
                                                     const char *lease,
                                                     const char *operation) {
  KCRLeaseReference *reference = KCRReference(version, lease, operation);
  if (raw == NULL || reference == nil || method < 0 || method > 3)
    return KCRFailure();
  KCRClient *client = (__bridge KCRClient *)raw;
  return KCRWait(
      client, ^(id<KCRRouteHelperProtocol> proxy, void (^reply)(KCRReply *)) {
        switch (method) {
        case 0:
          [proxy apply:reference reply:reply];
          break;
        case 1:
          [proxy rollback:reference reply:reply];
          break;
        case 2:
          [proxy heartbeat:reference reply:reply];
          break;
        case 3:
          [proxy status:reference reply:reply];
          break;
        }
      });
}
