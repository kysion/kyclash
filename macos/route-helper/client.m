#import <Foundation/Foundation.h>
#include <stdint.h>
#if defined(KYCLASH_ROUTE_HELPER_CLIENT_SELF_TEST)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#endif

static NSString *const KCRMachService = @"net.kysion.kyclash.route-helper";
static const int64_t KCRTimeoutNanoseconds = 5LL * NSEC_PER_SEC;
static const uint8_t KCRProtocolVersion = 2;

typedef struct {
  int32_t transport_status;
  int32_t protocol_version;
  int32_t state;
  int32_t error_code;
} KCRClientReply;

// Transport failures are deliberately separate from a typed helper reply.
// Rust treats every non-zero value as a failed native generation and must not
// replay an ambiguous route mutation.  Keep these values stable: the C ABI is
// consumed by the Rust production route boundary and by the signed VM lab.
typedef NS_ENUM(int32_t, KCRTransportStatus) {
  KCRTransportOK = 0,
  KCRTransportTimeout = 1,
  KCRTransportRemoteFailure = 2,
  KCRTransportInterrupted = 3,
  KCRTransportInvalidated = 4,
  KCRTransportProtocolFailure = 5,
  KCRTransportTerminal = 6,
  KCRTransportInvalidArgument = 7,
};

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
#if defined(KYCLASH_ROUTE_HELPER_CLIENT_SELF_TEST)
+ (instancetype)selfTestReplyWithProtocolVersion:(int32_t)protocolVersion
                                            state:(NSString *)state
                                        errorCode:(NSString *)errorCode;
#endif
@end

@implementation KCRReply
+ (BOOL)supportsSecureCoding {
  return YES;
}
#if defined(KYCLASH_ROUTE_HELPER_CLIENT_SELF_TEST)
+ (instancetype)selfTestReplyWithProtocolVersion:(int32_t)protocolVersion
                                            state:(NSString *)state
                                        errorCode:(NSString *)errorCode {
  KCRReply *reply = [[KCRReply alloc] init];
  reply->_protocolVersion = protocolVersion;
  reply->_state = [state copy];
  reply->_errorCode = [errorCode copy];
  return reply;
}
#endif
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

@interface KCRRequestCompletion : NSObject
@property(nonatomic, readonly) uint64_t requestID;
- (instancetype)initWithRequestID:(uint64_t)requestID;
- (BOOL)completeWithResult:(KCRClientReply)result;
- (BOOL)waitForNanoseconds:(int64_t)nanoseconds;
- (KCRClientReply)result;
@end

@implementation KCRRequestCompletion {
  NSLock *_stateLock;
  dispatch_semaphore_t _semaphore;
  BOOL _completed;
  KCRClientReply _result;
}

- (instancetype)initWithRequestID:(uint64_t)requestID {
  if ((self = [super init])) {
    _requestID = requestID;
    _stateLock = [[NSLock alloc] init];
    _semaphore = dispatch_semaphore_create(0);
    _completed = NO;
    _result = (KCRClientReply){.transport_status = KCRTransportTerminal,
                               .protocol_version = -1,
                               .state = -1,
                               .error_code = -1};
  }
  return self;
}

- (BOOL)completeWithResult:(KCRClientReply)result {
  [_stateLock lock];
  if (_completed) {
    [_stateLock unlock];
    return NO;
  }
  _completed = YES;
  _result = result;
  [_stateLock unlock];
  // The completion object owns the semaphore and signals it exactly once.
  // Callers may race a reply, timeout, and generation terminalization without
  // ever double-waking the waiter.
  dispatch_semaphore_signal(_semaphore);
  return YES;
}

- (BOOL)waitForNanoseconds:(int64_t)nanoseconds {
  return dispatch_semaphore_wait(
             _semaphore,
             dispatch_time(DISPATCH_TIME_NOW, nanoseconds)) == 0;
}

- (KCRClientReply)result {
  [_stateLock lock];
  KCRClientReply result = _result;
  [_stateLock unlock];
  return result;
}
@end

@interface KCRClient : NSObject {
  NSLock *_stateLock;
  NSMutableDictionary<NSNumber *, KCRRequestCompletion *> *_pending;
  uint64_t _nextRequestID;
  BOOL _terminal;
  KCRTransportStatus _terminalStatus;
}
@property(nonatomic, readonly) NSXPCConnection *connection;
- (KCRRequestCompletion *)beginRequestWithRejectedStatus:
    (KCRTransportStatus *)rejectedStatus;
- (void)finishRequest:(KCRRequestCompletion *)request reply:(KCRReply *)reply;
- (void)terminalize:(KCRTransportStatus)status;
- (void)close;
#if defined(KYCLASH_ROUTE_HELPER_CLIENT_SELF_TEST)
- (instancetype)initForSelfTest;
#endif
@end

static int32_t KCRStateCode(NSString *state);
static int32_t KCRErrorCode(NSString *error);
static KCRClientReply KCRFailureForTransport(KCRTransportStatus status);

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
    _stateLock = [[NSLock alloc] init];
    _pending = [[NSMutableDictionary alloc] init];
    _nextRequestID = 1;
    _terminal = NO;
    _terminalStatus = KCRTransportTerminal;
    _connection = [[NSXPCConnection alloc]
        initWithMachServiceName:KCRMachService
                        options:NSXPCConnectionPrivileged];
    _connection.remoteObjectInterface = KCRClientInterface();

    // The connection handlers are installed before resume.  A handler only
    // performs the one-way terminal transition; it never invokes a route
    // operation or creates a replacement connection.
    __weak KCRClient *weakSelf = self;
    _connection.interruptionHandler = ^{
      KCRClient *strongSelf = weakSelf;
      [strongSelf terminalize:KCRTransportInterrupted];
    };
    _connection.invalidationHandler = ^{
      KCRClient *strongSelf = weakSelf;
      [strongSelf terminalize:KCRTransportInvalidated];
    };
    [_connection resume];
  }
  return self;
}
#if defined(KYCLASH_ROUTE_HELPER_CLIENT_SELF_TEST)
- (instancetype)initForSelfTest {
  if ((self = [super init])) {
    _stateLock = [[NSLock alloc] init];
    _pending = [[NSMutableDictionary alloc] init];
    _nextRequestID = 1;
    _terminal = NO;
    _terminalStatus = KCRTransportTerminal;
    _connection = nil;
  }
  return self;
}
#endif
- (KCRRequestCompletion *)beginRequestWithRejectedStatus:
    (KCRTransportStatus *)rejectedStatus {
  [_stateLock lock];
  if (_terminal) {
    if (rejectedStatus != NULL)
      *rejectedStatus = _terminalStatus;
    [_stateLock unlock];
    return nil;
  }

  // A monotonically increasing ID prevents a late callback from an old
  // request being confused with a future request, even after wrapping would
  // otherwise make the dictionary key reusable.
  if (_nextRequestID == 0 || _nextRequestID == UINT64_MAX) {
    _terminal = YES;
    _terminalStatus = KCRTransportProtocolFailure;
    NSArray<KCRRequestCompletion *> *pending = _pending.allValues;
    [_pending removeAllObjects];
    KCRClientReply failure =
        KCRFailureForTransport(KCRTransportProtocolFailure);
    for (KCRRequestCompletion *request in pending)
      [request completeWithResult:failure];
    if (rejectedStatus != NULL)
      *rejectedStatus = _terminalStatus;
    [_stateLock unlock];
    return nil;
  }
  uint64_t requestID = _nextRequestID++;
  KCRRequestCompletion *request =
      [[KCRRequestCompletion alloc] initWithRequestID:requestID];
  _pending[@(requestID)] = request;
  [_stateLock unlock];
  return request;
}

- (void)finishRequest:(KCRRequestCompletion *)request reply:(KCRReply *)reply {
  if (request == nil)
    return;

  [_stateLock lock];
  KCRRequestCompletion *registered = _pending[@(request.requestID)];
  if (_terminal || registered != request) {
    // This includes callbacks arriving after terminalization and callbacks
    // racing a timeout after their waiter already won.  They are inert.
    [_stateLock unlock];
    return;
  }

  int32_t state = KCRStateCode(reply.state);
  int32_t error = KCRErrorCode(reply.errorCode);
  BOOL valid = reply != nil &&
               reply.protocolVersion == KCRProtocolVersion && state >= 0 &&
               error >= 0;
  if (!valid) {
    // Protocol failure is terminal for the whole generation.  Complete the
    // complete pending set while holding the same state lock that changes the
    // generation state; a callback cannot slip in between the transition and
    // the waiter wakeups.
    _terminal = YES;
    _terminalStatus = KCRTransportProtocolFailure;
    NSArray<KCRRequestCompletion *> *pending = _pending.allValues;
    [_pending removeAllObjects];
    KCRClientReply failure = KCRFailureForTransport(KCRTransportProtocolFailure);
    for (KCRRequestCompletion *candidate in pending)
      [candidate completeWithResult:failure];
    [_stateLock unlock];
    return;
  }

  [_pending removeObjectForKey:@(request.requestID)];
  KCRClientReply result = (KCRClientReply){
      .transport_status = KCRTransportOK,
      .protocol_version = reply.protocolVersion,
      .state = state,
      .error_code = error,
  };
  [request completeWithResult:result];
  [_stateLock unlock];
}

- (void)terminalize:(KCRTransportStatus)status {
  if (status == KCRTransportOK)
    status = KCRTransportTerminal;
  [_stateLock lock];
  if (_terminal) {
    [_stateLock unlock];
    return;
  }
  _terminal = YES;
  _terminalStatus = status;
  NSArray<KCRRequestCompletion *> *pending = _pending.allValues;
  [_pending removeAllObjects];
  KCRClientReply failure = KCRFailureForTransport(status);
  for (KCRRequestCompletion *request in pending)
    [request completeWithResult:failure];
  [_stateLock unlock];
}

- (void)close {
  [self terminalize:KCRTransportInvalidated];
  [_connection invalidate];
}

- (void)dealloc {
  [self close];
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

static KCRClientReply KCRFailureForTransport(KCRTransportStatus status) {
  return (KCRClientReply){.transport_status = status,
                          .protocol_version = -1,
                          .state = -1,
                          .error_code = -1};
}

static KCRClientReply KCRFailure(void) {
  return KCRFailureForTransport(KCRTransportInvalidArgument);
}

static KCRClientReply KCRWaitWithTimeout(
    KCRClient *client, int64_t timeoutNanoseconds,
    void (^invoke)(id<KCRRouteHelperProtocol>, void (^)(KCRReply *))) {
  if (client == nil)
    return KCRFailure();

  KCRTransportStatus rejectedStatus = KCRTransportTerminal;
  KCRRequestCompletion *request =
      [client beginRequestWithRejectedStatus:&rejectedStatus];
  if (request == nil)
    return KCRFailureForTransport(rejectedStatus);

  __weak KCRClient *weakClient = client;
  id<KCRRouteHelperProtocol> proxy = [client.connection
      remoteObjectProxyWithErrorHandler:^(__unused NSError *error) {
        KCRClient *strongClient = weakClient;
        [strongClient terminalize:KCRTransportRemoteFailure];
      }];
  invoke(proxy, ^(KCRReply *reply) {
    KCRClient *strongClient = weakClient;
    [strongClient finishRequest:request reply:reply];
  });

  // Timeout is itself a first-wins terminal event.  If a reply won the
  // request just before this deadline, terminalize still closes the
  // generation for any other waiters but leaves that request's reply intact.
  if (![request waitForNanoseconds:timeoutNanoseconds])
    [client terminalize:KCRTransportTimeout];
  return [request result];
}

static KCRClientReply KCRWait(KCRClient *client,
                              void (^invoke)(id<KCRRouteHelperProtocol>,
                                             void (^)(KCRReply *))) {
  return KCRWaitWithTimeout(client, KCRTimeoutNanoseconds, invoke);
}

void *kyclash_route_helper_client_create(void) {
  return (__bridge_retained void *)[[KCRClient alloc] init];
}

void kyclash_route_helper_client_destroy(void *raw) {
  if (raw != NULL) {
    KCRClient *client = CFBridgingRelease(raw);
    [client close];
  }
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

#if defined(KYCLASH_ROUTE_HELPER_CLIENT_SELF_TEST)

static void KCRSelfTestRequire(BOOL condition, const char *message) {
  if (condition)
    return;
  fprintf(stderr, "kyclash client self-test failed: %s\n", message);
  abort();
}

static KCRClientReply KCRSelfTestResult(KCRTransportStatus status) {
  return (KCRClientReply){.transport_status = status,
                          .protocol_version = -1,
                          .state = -1,
                          .error_code = -1};
}

static const KCRTransportStatus KCRSelfTestTerminalCauses[] = {
    KCRTransportTimeout,
    KCRTransportRemoteFailure,
    KCRTransportInterrupted,
    KCRTransportInvalidated,
    KCRTransportProtocolFailure,
};
static const NSUInteger KCRSelfTestTerminalCauseCount =
    sizeof(KCRSelfTestTerminalCauses) / sizeof(KCRSelfTestTerminalCauses[0]);

static void KCRSelfTestCompletionFirstWins(void) {
  // Pin one winner for each externally visible terminal cause so coverage is
  // deterministic; duplicate callbacks below still race that winner and
  // prove that they cannot signal a second time.
  for (NSUInteger causeIndex = 0;
       causeIndex < KCRSelfTestTerminalCauseCount; causeIndex++) {
    KCRTransportStatus expected = KCRSelfTestTerminalCauses[causeIndex];
    for (NSUInteger round = 0; round < 16; round++) {
      KCRRequestCompletion *request =
          [[KCRRequestCompletion alloc] initWithRequestID:round + 1];
      KCRSelfTestRequire(
          [request completeWithResult:KCRSelfTestResult(expected)],
          "deterministic first completion did not win");
      dispatch_group_t group = dispatch_group_create();
      NSLock *winnerLock = [[NSLock alloc] init];
      __block NSUInteger winnerCount = 1;
      for (NSUInteger index = 0; index < 32; index++) {
        KCRTransportStatus status =
            (KCRTransportStatus)(KCRTransportRemoteFailure + (index % 4));
        dispatch_group_async(
            group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
              BOOL won =
                  [request completeWithResult:KCRSelfTestResult(status)];
              if (won) {
                [winnerLock lock];
                winnerCount += 1;
                [winnerLock unlock];
              }
            });
      }
      long waitResult =
          dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW,
                                                     2LL * NSEC_PER_SEC));
      KCRSelfTestRequire(waitResult == 0, "completion racers did not finish");
      [winnerLock lock];
      NSUInteger winners = winnerCount;
      [winnerLock unlock];
      KCRSelfTestRequire(winners == 1, "completion was not first-wins");
      KCRClientReply result = [request result];
      KCRSelfTestRequire(result.transport_status == expected,
                         "first completion result was lost");
      KCRSelfTestRequire([request waitForNanoseconds:10LL * 1000LL * 1000LL],
                         "first completion did not wake its waiter");
      KCRSelfTestRequire(![request waitForNanoseconds:1LL * 1000LL * 1000LL],
                         "duplicate completion signalled a second time");
    }
  }
}

static void KCRSelfTestTerminalWakeAndLateReply(void) {
  KCRClient *client = [[KCRClient alloc] initForSelfTest];
  NSMutableArray<KCRRequestCompletion *> *requests =
      [NSMutableArray arrayWithCapacity:16];
  for (NSUInteger index = 0; index < 16; index++) {
    KCRTransportStatus rejected = KCRTransportTerminal;
    KCRRequestCompletion *request =
        [client beginRequestWithRejectedStatus:&rejected];
    KCRSelfTestRequire(request != nil && rejected == KCRTransportTerminal,
                       "live generation rejected a request");
    [requests addObject:request];
  }

  dispatch_group_t waiters = dispatch_group_create();
  NSLock *wakeLock = [[NSLock alloc] init];
  __block NSUInteger wakeCount = 0;
  for (KCRRequestCompletion *request in requests) {
    dispatch_group_async(
        waiters, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
          BOOL woke = [request waitForNanoseconds:2LL * NSEC_PER_SEC];
          KCRSelfTestRequire(woke, "terminal did not wake a pending waiter");
          KCRSelfTestRequire(
              [request result].transport_status == KCRTransportInterrupted,
              "terminal cause was not retained by a pending waiter");
          KCRSelfTestRequire(
              ![request waitForNanoseconds:1LL * 1000LL * 1000LL],
              "terminal completion signalled more than once");
          [wakeLock lock];
          wakeCount += 1;
          [wakeLock unlock];
        });
  }
  // Give the waiter blocks an opportunity to enter their semaphore waits so
  // the test covers both pre- and post-terminal scheduling.
  usleep(1000);
  [client terminalize:KCRTransportInterrupted];
  long waitResult =
      dispatch_group_wait(waiters, dispatch_time(DISPATCH_TIME_NOW,
                                                   3LL * NSEC_PER_SEC));
  KCRSelfTestRequire(waitResult == 0, "terminal waiters did not drain");
  [wakeLock lock];
  NSUInteger wakes = wakeCount;
  [wakeLock unlock];
  KCRSelfTestRequire(wakes == requests.count,
                     "terminal did not release every waiter exactly once");

  KCRTransportStatus rejected = KCRTransportTerminal;
  KCRRequestCompletion *newRequest =
      [client beginRequestWithRejectedStatus:&rejected];
  KCRSelfTestRequire(newRequest == nil &&
                         rejected == KCRTransportInterrupted,
                     "terminal generation accepted a new request");

  // A callback arriving after the terminal transition must be inert, even if
  // it carries a perfectly valid protocol reply.
  KCRReply *lateReply =
      [KCRReply selfTestReplyWithProtocolVersion:KCRProtocolVersion
                                            state:@"idle"
                                        errorCode:nil];
  KCRRequestCompletion *oldRequest = requests.firstObject;
  [client finishRequest:oldRequest reply:lateReply];
  KCRSelfTestRequire([oldRequest result].transport_status ==
                         KCRTransportInterrupted,
                     "late reply changed a terminal waiter");
  [client close];
}

static void KCRSelfTestInvalidProtocolTerminal(void) {
  KCRClient *client = [[KCRClient alloc] initForSelfTest];
  KCRTransportStatus rejected = KCRTransportTerminal;
  KCRRequestCompletion *first =
      [client beginRequestWithRejectedStatus:&rejected];
  KCRRequestCompletion *second =
      [client beginRequestWithRejectedStatus:&rejected];
  KCRSelfTestRequire(first != nil && second != nil,
                     "invalid-protocol setup did not create waiters");
  KCRReply *invalid =
      [KCRReply selfTestReplyWithProtocolVersion:KCRProtocolVersion - 1
                                            state:@"idle"
                                        errorCode:nil];
  [client finishRequest:first reply:invalid];
  KCRSelfTestRequire([first result].transport_status ==
                         KCRTransportProtocolFailure,
                     "invalid protocol did not fail its request");
  KCRSelfTestRequire([second result].transport_status ==
                         KCRTransportProtocolFailure,
                     "invalid protocol did not wake all waiters");
  KCRSelfTestRequire([first waitForNanoseconds:10LL * 1000LL * 1000LL],
                     "invalid protocol did not signal first waiter");
  KCRSelfTestRequire(![first waitForNanoseconds:1LL * 1000LL * 1000LL],
                     "invalid protocol signalled first waiter twice");
  KCRSelfTestRequire([second waitForNanoseconds:10LL * 1000LL * 1000LL],
                     "invalid protocol did not signal second waiter");
  KCRSelfTestRequire(![second waitForNanoseconds:1LL * 1000LL * 1000LL],
                     "invalid protocol signalled second waiter twice");
  KCRTransportStatus terminalCause = KCRTransportTerminal;
  KCRRequestCompletion *newRequest =
      [client beginRequestWithRejectedStatus:&terminalCause];
  KCRSelfTestRequire(newRequest == nil &&
                         terminalCause == KCRTransportProtocolFailure,
                     "invalid protocol left generation live");
  KCRReply *late =
      [KCRReply selfTestReplyWithProtocolVersion:KCRProtocolVersion
                                            state:@"idle"
                                        errorCode:nil];
  [client finishRequest:first reply:late];
  KCRSelfTestRequire([first result].transport_status ==
                         KCRTransportProtocolFailure,
                     "late valid reply changed protocol failure");
  [client close];
}

static void KCRSelfTestTimeoutDeadlineAndReplyFirst(void) {
  KCRReply *reply =
      [KCRReply selfTestReplyWithProtocolVersion:KCRProtocolVersion
                                            state:@"idle"
                                        errorCode:nil];

  // Exercise the actual KCRWait deadline path with a self-test client that
  // never invokes its callback. The timeout must terminalize the generation,
  // wake the waiter, and reject every subsequent request with the exact cause.
  KCRClient *timeoutClient = [[KCRClient alloc] initForSelfTest];
  KCRClientReply timedOut = KCRWaitWithTimeout(
      timeoutClient, 5LL * NSEC_PER_MSEC,
      ^(id<KCRRouteHelperProtocol> proxy, void (^callback)(KCRReply *)) {
        (void)proxy;
        (void)callback;
      });
  KCRSelfTestRequire(timedOut.transport_status == KCRTransportTimeout,
                     "KCRWait did not report its timeout cause");
  KCRTransportStatus rejected = KCRTransportTerminal;
  KCRSelfTestRequire(
      [timeoutClient beginRequestWithRejectedStatus:&rejected] == nil &&
          rejected == KCRTransportTimeout,
      "timeout did not terminalize the native generation");
  [timeoutClient close];

  // A synchronous valid reply wins before the same deadline; terminalizing
  // afterward closes the generation but must not rewrite that completed
  // request's successful result.
  KCRClient *replyClient = [[KCRClient alloc] initForSelfTest];
  KCRClientReply replied = KCRWaitWithTimeout(
      replyClient, 100LL * NSEC_PER_MSEC,
      ^(id<KCRRouteHelperProtocol> proxy, void (^callback)(KCRReply *)) {
        (void)proxy;
        callback(reply);
      });
  KCRSelfTestRequire(replied.transport_status == KCRTransportOK,
                     "valid reply did not win before timeout");
  [replyClient terminalize:KCRTransportTimeout];
  rejected = KCRTransportTerminal;
  KCRSelfTestRequire(
      [replyClient beginRequestWithRejectedStatus:&rejected] == nil &&
          rejected == KCRTransportTimeout,
      "post-reply timeout did not close the generation");
  [replyClient close];

  // A callback arriving after the deadline is late and must remain inert.
  KCRClient *lateClient = [[KCRClient alloc] initForSelfTest];
  KCRClientReply late = KCRWaitWithTimeout(
      lateClient, 5LL * NSEC_PER_MSEC,
      ^(id<KCRRouteHelperProtocol> proxy, void (^callback)(KCRReply *)) {
        (void)proxy;
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, 50LL * NSEC_PER_MSEC),
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
              callback(reply);
            });
      });
  KCRSelfTestRequire(late.transport_status == KCRTransportTimeout,
                     "late callback unexpectedly beat timeout");
  usleep(100LL * 1000LL);
  KCRSelfTestRequire(late.transport_status == KCRTransportTimeout,
                     "late callback rewrote timeout result");
  [lateClient close];
}

static void KCRSelfTestReplyTerminalRaces(void) {
  // Exercise both deterministic winner orders for every externally visible
  // terminal cause. This includes timeout (the local deadline winner), remote
  // proxy failure, interruption, invalidation, and invalid-protocol failure.
  for (NSUInteger causeIndex = 0;
       causeIndex < KCRSelfTestTerminalCauseCount; causeIndex++) {
    KCRTransportStatus expected = KCRSelfTestTerminalCauses[causeIndex];
    KCRReply *reply =
        [KCRReply selfTestReplyWithProtocolVersion:KCRProtocolVersion
                                              state:@"idle"
                                          errorCode:nil];

    // Terminal event wins before the reply callback.
    KCRClient *terminalFirstClient = [[KCRClient alloc] initForSelfTest];
    KCRTransportStatus rejected = KCRTransportTerminal;
    KCRRequestCompletion *terminalFirst =
        [terminalFirstClient beginRequestWithRejectedStatus:&rejected];
    KCRSelfTestRequire(terminalFirst != nil,
                       "terminal-first setup did not create waiter");
    [terminalFirstClient terminalize:expected];
    KCRSelfTestRequire([terminalFirst result].transport_status == expected,
                       "terminal-first cause was not retained");
    [terminalFirstClient finishRequest:terminalFirst reply:reply];
    KCRSelfTestRequire([terminalFirst result].transport_status == expected,
                       "late reply changed terminal-first result");
    rejected = KCRTransportTerminal;
    KCRSelfTestRequire(
        [terminalFirstClient beginRequestWithRejectedStatus:&rejected] == nil &&
            rejected == expected,
        "terminal-first generation accepted a new request");
    KCRSelfTestRequire([terminalFirst waitForNanoseconds:10LL * 1000LL * 1000LL],
                       "terminal-first event did not wake waiter");
    KCRSelfTestRequire(![terminalFirst waitForNanoseconds:1LL * 1000LL * 1000LL],
                       "terminal-first event woke waiter twice");
    [terminalFirstClient close];

    // A valid reply wins its own waiter, then a terminal event still closes
    // the generation for all future requests without rewriting that result.
    KCRClient *replyFirstClient = [[KCRClient alloc] initForSelfTest];
    rejected = KCRTransportTerminal;
    KCRRequestCompletion *replyFirst =
        [replyFirstClient beginRequestWithRejectedStatus:&rejected];
    KCRSelfTestRequire(replyFirst != nil,
                       "reply-first setup did not create waiter");
    [replyFirstClient finishRequest:replyFirst reply:reply];
    KCRSelfTestRequire([replyFirst result].transport_status == KCRTransportOK,
                       "valid reply did not win its waiter");
    [replyFirstClient terminalize:expected];
    KCRSelfTestRequire([replyFirst result].transport_status == KCRTransportOK,
                       "terminal event rewrote a completed reply");
    rejected = KCRTransportTerminal;
    KCRSelfTestRequire(
        [replyFirstClient beginRequestWithRejectedStatus:&rejected] == nil &&
            rejected == expected,
        "reply-first terminal event did not close generation");
    KCRSelfTestRequire([replyFirst waitForNanoseconds:10LL * 1000LL * 1000LL],
                       "reply-first callback did not wake waiter");
    KCRSelfTestRequire(![replyFirst waitForNanoseconds:1LL * 1000LL * 1000LL],
                       "reply-first callback woke waiter twice");
    [replyFirstClient close];
  }

  // Finally race a valid callback against each terminal cause. The winner is
  // intentionally scheduler-dependent, but the result is restricted to the
  // exact two legal first-wins outcomes and a late callback is inert.
  for (NSUInteger round = 0; round < 128; round++) {
    KCRTransportStatus expected =
        KCRSelfTestTerminalCauses[round % KCRSelfTestTerminalCauseCount];
    KCRClient *client = [[KCRClient alloc] initForSelfTest];
    KCRTransportStatus rejected = KCRTransportTerminal;
    KCRRequestCompletion *request =
        [client beginRequestWithRejectedStatus:&rejected];
    KCRSelfTestRequire(request != nil, "race setup did not create waiter");
    KCRReply *reply =
        [KCRReply selfTestReplyWithProtocolVersion:KCRProtocolVersion
                                              state:@"idle"
                                          errorCode:nil];
    dispatch_group_t racers = dispatch_group_create();
    dispatch_group_async(
        racers, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
          [client finishRequest:request reply:reply];
        });
    dispatch_group_async(
        racers, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
          [client terminalize:expected];
        });
    long waitResult =
        dispatch_group_wait(racers, dispatch_time(DISPATCH_TIME_NOW,
                                                   2LL * NSEC_PER_SEC));
    KCRSelfTestRequire(waitResult == 0, "reply/terminal race did not finish");
    KCRClientReply result = [request result];
    KCRSelfTestRequire(result.transport_status == KCRTransportOK ||
                           result.transport_status == expected,
                       "reply/terminal race produced an impossible status");
    rejected = KCRTransportTerminal;
    KCRSelfTestRequire(
        [client beginRequestWithRejectedStatus:&rejected] == nil &&
            rejected == expected,
        "reply/terminal race did not terminalize its generation");
    // A callback after either winner is inert and cannot alter the result.
    [client finishRequest:request reply:reply];
    KCRSelfTestRequire([request result].transport_status ==
                           result.transport_status,
                       "late race callback changed the result");
    KCRSelfTestRequire([request waitForNanoseconds:10LL * 1000LL * 1000LL],
                       "reply/terminal race did not wake waiter");
    KCRSelfTestRequire(![request waitForNanoseconds:1LL * 1000LL * 1000LL],
                       "reply/terminal race woke waiter twice");
    [client close];
  }
}

int main(void) {
  @autoreleasepool {
    KCRSelfTestCompletionFirstWins();
    KCRSelfTestTerminalWakeAndLateReply();
    KCRSelfTestInvalidProtocolTerminal();
    KCRSelfTestTimeoutDeadlineAndReplyFirst();
    KCRSelfTestReplyTerminalRaces();
    puts("kyclash_route_helper_client_self_test=passed");
  }
  return 0;
}

#endif
