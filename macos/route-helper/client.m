#import <Foundation/Foundation.h>

static NSString *const KCRMachService = @"net.kysion.kyclash.route-helper";
static const int64_t KCRTimeoutNanoseconds = 5LL * NSEC_PER_SEC;

typedef struct {
  int32_t transport_status;
  int32_t state;
  int32_t error_code;
} KCRClientReply;

@interface KCRLeaseReference : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t version;
@property(nonatomic, copy, readonly) NSString *leaseID;
@property(nonatomic, copy, readonly) NSString *operationID;
- (instancetype)initWithVersion:(uint8_t)version
                         leaseID:(NSString *)leaseID
                     operationID:(NSString *)operationID;
@end

@implementation KCRLeaseReference
+ (BOOL)supportsSecureCoding { return YES; }
- (instancetype)initWithVersion:(uint8_t)version
                         leaseID:(NSString *)leaseID
                     operationID:(NSString *)operationID {
  if ((self = [super init])) {
    _version = version;
    _leaseID = [leaseID copy];
    _operationID = [operationID copy];
  }
  return self;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  return [self initWithVersion:(uint8_t)[coder decodeIntegerForKey:@"version"]
                       leaseID:[coder decodeObjectOfClass:NSString.class forKey:@"leaseID"]
                   operationID:[coder decodeObjectOfClass:NSString.class forKey:@"operationID"]];
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
@property(nonatomic, readonly) uint64_t profileRevision;
@property(nonatomic, copy, readonly) NSArray<NSString *> *privateCIDRs;
- (instancetype)initWithReference:(KCRLeaseReference *)reference
                 sidecarInstanceID:(NSString *)sidecarInstanceID
                     interfaceName:(NSString *)interfaceName
                 tunnelOperationID:(NSString *)tunnelOperationID
                               mtu:(uint16_t)mtu
                   profileRevision:(uint64_t)profileRevision
                      privateCIDRs:(NSArray<NSString *> *)privateCIDRs;
@end

@implementation KCRLeaseOwner
+ (BOOL)supportsSecureCoding { return YES; }
- (instancetype)initWithReference:(KCRLeaseReference *)reference
                 sidecarInstanceID:(NSString *)sidecarInstanceID
                     interfaceName:(NSString *)interfaceName
                 tunnelOperationID:(NSString *)tunnelOperationID
                               mtu:(uint16_t)mtu
                   profileRevision:(uint64_t)profileRevision
                      privateCIDRs:(NSArray<NSString *> *)privateCIDRs {
  if ((self = [super init])) {
    _reference = reference;
    _sidecarInstanceID = [sidecarInstanceID copy];
    _interfaceName = [interfaceName copy];
    _tunnelOperationID = [tunnelOperationID copy];
    _mtu = mtu;
    _profileRevision = profileRevision;
    _privateCIDRs = [privateCIDRs copy];
  }
  return self;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  NSSet *cidrClasses = [NSSet setWithObjects:NSArray.class, NSString.class, nil];
  return [self initWithReference:[coder decodeObjectOfClass:KCRLeaseReference.class forKey:@"reference"]
               sidecarInstanceID:[coder decodeObjectOfClass:NSString.class forKey:@"sidecarInstanceID"]
                   interfaceName:[coder decodeObjectOfClass:NSString.class forKey:@"interfaceName"]
               tunnelOperationID:[coder decodeObjectOfClass:NSString.class forKey:@"tunnelOperationID"]
                             mtu:(uint16_t)[coder decodeIntegerForKey:@"mtu"]
                 profileRevision:(uint64_t)[coder decodeInt64ForKey:@"profileRevision"]
                    privateCIDRs:[coder decodeObjectOfClasses:cidrClasses forKey:@"privateCIDRs"]];
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:_reference forKey:@"reference"];
  [coder encodeObject:_sidecarInstanceID forKey:@"sidecarInstanceID"];
  [coder encodeObject:_interfaceName forKey:@"interfaceName"];
  [coder encodeObject:_tunnelOperationID forKey:@"tunnelOperationID"];
  [coder encodeInteger:_mtu forKey:@"mtu"];
  [coder encodeInt64:(int64_t)_profileRevision forKey:@"profileRevision"];
  [coder encodeObject:_privateCIDRs forKey:@"privateCIDRs"];
}
@end

@interface KCRReply : NSObject <NSSecureCoding>
@property(nonatomic, copy, readonly) NSString *state;
@property(nonatomic, copy, readonly, nullable) NSString *errorCode;
@end

@implementation KCRReply
+ (BOOL)supportsSecureCoding { return YES; }
- (instancetype)initWithCoder:(NSCoder *)coder {
  if ((self = [super init])) {
    _state = [[coder decodeObjectOfClass:NSString.class forKey:@"state"] copy];
    _errorCode = [[coder decodeObjectOfClass:NSString.class forKey:@"errorCode"] copy];
  }
  return self;
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:_state forKey:@"state"];
  [coder encodeObject:_errorCode forKey:@"errorCode"];
}
@end

@protocol KCRRouteHelperProtocol
- (void)discoverWithReply:(void (^)(KCRReply *))reply;
- (void)begin:(KCRLeaseOwner *)owner reply:(void (^)(KCRReply *))reply;
- (void)apply:(KCRLeaseReference *)reference reply:(void (^)(KCRReply *))reply;
- (void)rollback:(KCRLeaseReference *)reference reply:(void (^)(KCRReply *))reply;
- (void)recover:(KCRLeaseOwner *)owner reply:(void (^)(KCRReply *))reply;
- (void)heartbeat:(KCRLeaseReference *)reference reply:(void (^)(KCRReply *))reply;
- (void)status:(KCRLeaseReference *)reference reply:(void (^)(KCRReply *))reply;
@end

@interface KCRClient : NSObject
@property(nonatomic, readonly) NSXPCConnection *connection;
@end

static NSXPCInterface *KCRClientInterface(void) {
  NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:@protocol(KCRRouteHelperProtocol)];
  NSSet *reply = [NSSet setWithObject:KCRReply.class];
  NSSet *owner = [NSSet setWithObjects:KCRLeaseOwner.class, KCRLeaseReference.class, NSArray.class, NSString.class, nil];
  NSSet *reference = [NSSet setWithObjects:KCRLeaseReference.class, NSString.class, nil];
  [interface setClasses:reply forSelector:@selector(discoverWithReply:) argumentIndex:0 ofReply:YES];
  for (NSString *selectorName in @[@"begin:reply:", @"recover:reply:"]) {
    SEL selector = NSSelectorFromString(selectorName);
    [interface setClasses:owner forSelector:selector argumentIndex:0 ofReply:NO];
    [interface setClasses:reply forSelector:selector argumentIndex:0 ofReply:YES];
  }
  for (NSString *selectorName in @[@"apply:reply:", @"rollback:reply:", @"heartbeat:reply:", @"status:reply:"]) {
    SEL selector = NSSelectorFromString(selectorName);
    [interface setClasses:reference forSelector:selector argumentIndex:0 ofReply:NO];
    [interface setClasses:reply forSelector:selector argumentIndex:0 ofReply:YES];
  }
  return interface;
}

@implementation KCRClient
- (instancetype)init {
  if ((self = [super init])) {
    _connection = [[NSXPCConnection alloc] initWithMachServiceName:KCRMachService
                                                           options:NSXPCConnectionPrivileged];
    _connection.remoteObjectInterface = KCRClientInterface();
    [_connection resume];
  }
  return self;
}
- (void)dealloc { [_connection invalidate]; }
@end

static int32_t KCRStateCode(NSString *state) {
  if ([state isEqualToString:@"idle"]) return 0;
  if ([state isEqualToString:@"prepared"]) return 1;
  if ([state isEqualToString:@"applied"]) return 2;
  if ([state isEqualToString:@"rolling_back"]) return 3;
  if ([state isEqualToString:@"failed_closed"]) return 4;
  return -1;
}

static int32_t KCRErrorCode(NSString *error) {
  if (error == nil) return 0;
  if ([error isEqualToString:@"not_ready"]) return 1;
  if ([error isEqualToString:@"invalid_owner"]) return 2;
  if ([error isEqualToString:@"ownership_mismatch"]) return 3;
  return -1;
}

static KCRClientReply KCRFailure(void) {
  return (KCRClientReply){.transport_status = -1, .state = -1, .error_code = -1};
}

static KCRClientReply KCRWait(KCRClient *client, void (^invoke)(id<KCRRouteHelperProtocol>, void (^)(KCRReply *))) {
  if (client == nil) return KCRFailure();
  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
  __block KCRClientReply result = KCRFailure();
  id<KCRRouteHelperProtocol> proxy = [client.connection remoteObjectProxyWithErrorHandler:^(__unused NSError *error) {
    dispatch_semaphore_signal(semaphore);
  }];
  invoke(proxy, ^(KCRReply *reply) {
    result = (KCRClientReply){.transport_status = 0, .state = KCRStateCode(reply.state), .error_code = KCRErrorCode(reply.errorCode)};
    dispatch_semaphore_signal(semaphore);
  });
  if (dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, KCRTimeoutNanoseconds)) != 0) {
    return KCRFailure();
  }
  return result;
}

void *kyclash_route_helper_client_create(void) {
  return (__bridge_retained void *)[[KCRClient alloc] init];
}

void kyclash_route_helper_client_destroy(void *raw) {
  if (raw != NULL) CFBridgingRelease(raw);
}

KCRClientReply kyclash_route_helper_client_discover(void *raw) {
  KCRClient *client = (__bridge KCRClient *)raw;
  return KCRWait(client, ^(id<KCRRouteHelperProtocol> proxy, void (^reply)(KCRReply *)) {
    [proxy discoverWithReply:reply];
  });
}

static KCRLeaseReference *KCRReference(uint8_t version, const char *lease, const char *operation) {
  if (lease == NULL || operation == NULL) return nil;
  return [[KCRLeaseReference alloc] initWithVersion:version
                                           leaseID:[NSString stringWithUTF8String:lease]
                                       operationID:[NSString stringWithUTF8String:operation]];
}

KCRClientReply kyclash_route_helper_client_owner(void *raw, int32_t method,
                                                  uint8_t version, const char *lease,
                                                  const char *operation, const char *instance,
                                                  const char *interface_name, const char *tunnel_operation,
                                                  uint16_t mtu, uint64_t revision,
                                                  const char *const *cidrs, uintptr_t cidr_count) {
  if (raw == NULL || method < 0 || method > 1 || instance == NULL || interface_name == NULL || tunnel_operation == NULL ||
      cidrs == NULL || cidr_count == 0 || cidr_count > 64) return KCRFailure();
  KCRLeaseReference *reference = KCRReference(version, lease, operation);
  NSMutableArray<NSString *> *values = [NSMutableArray arrayWithCapacity:cidr_count];
  for (uintptr_t index = 0; index < cidr_count; index++) {
    if (cidrs[index] == NULL) return KCRFailure();
    NSString *value = [NSString stringWithUTF8String:cidrs[index]];
    if (value == nil) return KCRFailure();
    [values addObject:value];
  }
  KCRLeaseOwner *owner = [[KCRLeaseOwner alloc]
      initWithReference:reference
      sidecarInstanceID:[NSString stringWithUTF8String:instance]
      interfaceName:[NSString stringWithUTF8String:interface_name]
      tunnelOperationID:[NSString stringWithUTF8String:tunnel_operation]
      mtu:mtu
      profileRevision:revision
      privateCIDRs:values];
  KCRClient *client = (__bridge KCRClient *)raw;
  return KCRWait(client, ^(id<KCRRouteHelperProtocol> proxy, void (^reply)(KCRReply *)) {
    if (method == 0) {
      [proxy begin:owner reply:reply];
    } else {
      [proxy recover:owner reply:reply];
    }
  });
}

KCRClientReply kyclash_route_helper_client_reference(void *raw, int32_t method, uint8_t version,
                                                      const char *lease, const char *operation) {
  KCRLeaseReference *reference = KCRReference(version, lease, operation);
  if (raw == NULL || reference == nil || method < 0 || method > 3) return KCRFailure();
  KCRClient *client = (__bridge KCRClient *)raw;
  return KCRWait(client, ^(id<KCRRouteHelperProtocol> proxy, void (^reply)(KCRReply *)) {
    switch (method) {
      case 0: [proxy apply:reference reply:reply]; break;
      case 1: [proxy rollback:reference reply:reply]; break;
      case 2: [proxy heartbeat:reference reply:reply]; break;
      case 3: [proxy status:reference reply:reply]; break;
    }
  });
}
