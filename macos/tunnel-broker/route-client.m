// Typed root-to-root route hold bridge for the reviewed route-helper v3
// contract.  This file is deliberately separate from client.m: client.m is
// the App/session v1 surface, while this bridge must never be reachable from
// an App connection or accept a generic command/path/dictionary.
//
// The current Swift broker target still exports the v1 TunnelRouteBinding
// protocol.  The v3 selectors/classes below are a source contract only until
// the reviewed Swift route service is enabled.  The Rust production
// composition does not call this bridge yet; a v1 reply is therefore a
// protocol failure rather than an implicit downgrade.

#import <Foundation/Foundation.h>

#include <stdint.h>
#include <string.h>

static NSString *const KCTBRMachService =
    @"net.kysion.kyclash.tunnel-broker";
static const int64_t KCTBRTimeoutNanoseconds = 5LL * NSEC_PER_SEC;
static const int32_t KCTBRRouteProtocolVersion = 3;
static const int32_t KCTBRBrokerProtocolVersion = 1;
static const size_t KCTBRMaximumIdentifierBytes = 64;

typedef struct {
  int32_t transport_status;
  int32_t protocol_version;
  int32_t broker_protocol_version;
  int32_t state;
  int32_t error_code;
  uint64_t broker_generation;
  char sidecar_instance_id[65];
  char route_lease_id[65];
  char operation_id[65];
} KCTBRClientReply;

typedef NS_ENUM(int32_t, KCTBRTransportStatus) {
  KCTBRTransportOK = 0,
  KCTBRTransportTimeout = 1,
  KCTBRTransportRemoteFailure = 2,
  KCTBRTransportInterrupted = 3,
  KCTBRTransportInvalidated = 4,
  KCTBRTransportProtocolFailure = 5,
  KCTBRTransportTerminal = 6,
  KCTBRTransportInvalidArgument = 7,
};

@interface KCTunnelRouteBindingV3 : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t protocolVersion;
@property(nonatomic, readonly) uint8_t brokerProtocolVersion;
@property(nonatomic, readonly) uint64_t brokerGeneration;
@property(nonatomic, copy, readonly) NSString *sidecarInstanceID;
@property(nonatomic, copy, readonly) NSString *routeLeaseID;
@property(nonatomic, copy, readonly) NSString *operationID;
- (instancetype)initWithProtocolVersion:(uint8_t)protocolVersion
                  brokerProtocolVersion:(uint8_t)brokerProtocolVersion
                        brokerGeneration:(uint64_t)brokerGeneration
                       sidecarInstanceID:(NSString *)sidecarInstanceID
                            routeLeaseID:(NSString *)routeLeaseID
                             operationID:(NSString *)operationID;
@end

@implementation KCTunnelRouteBindingV3
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithProtocolVersion:(uint8_t)protocolVersion
                  brokerProtocolVersion:(uint8_t)brokerProtocolVersion
                        brokerGeneration:(uint64_t)brokerGeneration
                       sidecarInstanceID:(NSString *)sidecarInstanceID
                            routeLeaseID:(NSString *)routeLeaseID
                             operationID:(NSString *)operationID {
  if (sidecarInstanceID == nil || routeLeaseID == nil || operationID == nil)
    return nil;
  if ((self = [super init])) {
    _protocolVersion = protocolVersion;
    _brokerProtocolVersion = brokerProtocolVersion;
    _brokerGeneration = brokerGeneration;
    _sidecarInstanceID = [sidecarInstanceID copy];
    _routeLeaseID = [routeLeaseID copy];
    _operationID = [operationID copy];
  }
  return self;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"] ||
      ![coder containsValueForKey:@"brokerProtocolVersion"] ||
      ![coder containsValueForKey:@"brokerGeneration"])
    return nil;
  NSInteger routeVersion = [coder decodeIntegerForKey:@"protocolVersion"];
  NSInteger brokerVersion =
      [coder decodeIntegerForKey:@"brokerProtocolVersion"];
  int64_t rawGeneration = [coder decodeInt64ForKey:@"brokerGeneration"];
  NSString *sidecar =
      [coder decodeObjectOfClass:NSString.class forKey:@"sidecarInstanceID"];
  NSString *lease =
      [coder decodeObjectOfClass:NSString.class forKey:@"routeLeaseID"];
  NSString *operation =
      [coder decodeObjectOfClass:NSString.class forKey:@"operationID"];
  if (routeVersion < 0 || routeVersion > UINT8_MAX || brokerVersion < 0 ||
      brokerVersion > UINT8_MAX || rawGeneration <= 0 || sidecar == nil ||
      lease == nil || operation == nil)
    return nil;
  return [self initWithProtocolVersion:(uint8_t)routeVersion
                 brokerProtocolVersion:(uint8_t)brokerVersion
                       brokerGeneration:(uint64_t)rawGeneration
                      sidecarInstanceID:sidecar
                           routeLeaseID:lease
                            operationID:operation];
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_protocolVersion forKey:@"protocolVersion"];
  [coder encodeInteger:_brokerProtocolVersion forKey:@"brokerProtocolVersion"];
  [coder encodeInt64:(int64_t)_brokerGeneration forKey:@"brokerGeneration"];
  [coder encodeObject:_sidecarInstanceID forKey:@"sidecarInstanceID"];
  [coder encodeObject:_routeLeaseID forKey:@"routeLeaseID"];
  [coder encodeObject:_operationID forKey:@"operationID"];
}
@end

// Unlike the v1 TunnelBrokerReply, a v3 reply echoes the complete binding.
// The Rust side rejects a reply that omits or changes any identity field.
@interface KCTunnelBrokerRouteReplyV3 : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t protocolVersion;
@property(nonatomic, readonly) uint8_t brokerProtocolVersion;
@property(nonatomic, readonly) uint64_t brokerGeneration;
@property(nonatomic, copy, readonly) NSString *state;
@property(nonatomic, copy, readonly, nullable) NSString *errorCode;
@property(nonatomic, copy, readonly) NSString *sidecarInstanceID;
@property(nonatomic, copy, readonly) NSString *routeLeaseID;
@property(nonatomic, copy, readonly) NSString *operationID;
@end

@implementation KCTunnelBrokerRouteReplyV3
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"] ||
      ![coder containsValueForKey:@"brokerProtocolVersion"] ||
      ![coder containsValueForKey:@"brokerGeneration"])
    return nil;
  NSInteger routeVersion = [coder decodeIntegerForKey:@"protocolVersion"];
  NSInteger brokerVersion =
      [coder decodeIntegerForKey:@"brokerProtocolVersion"];
  int64_t rawGeneration = [coder decodeInt64ForKey:@"brokerGeneration"];
  NSString *state = [coder decodeObjectOfClass:NSString.class forKey:@"state"];
  NSString *error =
      [coder decodeObjectOfClass:NSString.class forKey:@"errorCode"];
  NSString *sidecar =
      [coder decodeObjectOfClass:NSString.class forKey:@"sidecarInstanceID"];
  NSString *lease =
      [coder decodeObjectOfClass:NSString.class forKey:@"routeLeaseID"];
  NSString *operation =
      [coder decodeObjectOfClass:NSString.class forKey:@"operationID"];
  if (routeVersion < 0 || routeVersion > UINT8_MAX || brokerVersion < 0 ||
      brokerVersion > UINT8_MAX || rawGeneration <= 0 || state == nil ||
      sidecar == nil || lease == nil || operation == nil)
    return nil;
  if ((self = [super init])) {
    _protocolVersion = (uint8_t)routeVersion;
    _brokerProtocolVersion = (uint8_t)brokerVersion;
    _brokerGeneration = (uint64_t)rawGeneration;
    _state = [state copy];
    _errorCode = [error copy];
    _sidecarInstanceID = [sidecar copy];
    _routeLeaseID = [lease copy];
    _operationID = [operation copy];
  }
  return self;
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_protocolVersion forKey:@"protocolVersion"];
  [coder encodeInteger:_brokerProtocolVersion forKey:@"brokerProtocolVersion"];
  [coder encodeInt64:(int64_t)_brokerGeneration forKey:@"brokerGeneration"];
  [coder encodeObject:_state forKey:@"state"];
  if (_errorCode != nil)
    [coder encodeObject:_errorCode forKey:@"errorCode"];
  [coder encodeObject:_sidecarInstanceID forKey:@"sidecarInstanceID"];
  [coder encodeObject:_routeLeaseID forKey:@"routeLeaseID"];
  [coder encodeObject:_operationID forKey:@"operationID"];
}
@end

@protocol KCTunnelBrokerRouteV3Protocol
- (void)holdV3:(KCTunnelRouteBindingV3 *)binding
          reply:(void (^)(KCTunnelBrokerRouteReplyV3 *))reply;
- (void)releaseV3:(KCTunnelRouteBindingV3 *)binding
            reply:(void (^)(KCTunnelBrokerRouteReplyV3 *))reply;
- (void)statusV3:(KCTunnelRouteBindingV3 *)binding
           reply:(void (^)(KCTunnelBrokerRouteReplyV3 *))reply;
@end

static BOOL KCTBRValidIdentifier(NSString *value) {
  if (value == nil)
    return NO;
  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
  if (data == nil || data.length < 8 ||
      data.length > KCTBRMaximumIdentifierBytes)
    return NO;
  const uint8_t *bytes = data.bytes;
  for (NSUInteger index = 0; index < data.length; index++) {
    uint8_t byte = bytes[index];
    if (!((byte >= '0' && byte <= '9') ||
          (byte >= 'A' && byte <= 'Z') ||
          (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '.' ||
          byte == '_'))
      return NO;
  }
  return YES;
}

static BOOL KCTBRValidBinding(KCTunnelRouteBindingV3 *binding) {
  return binding != nil &&
         binding.protocolVersion == KCTBRRouteProtocolVersion &&
         binding.brokerProtocolVersion == KCTBRBrokerProtocolVersion &&
         binding.brokerGeneration > 0 &&
         binding.brokerGeneration <= INT64_MAX &&
         KCTBRValidIdentifier(binding.sidecarInstanceID) &&
         KCTBRValidIdentifier(binding.routeLeaseID) &&
         KCTBRValidIdentifier(binding.operationID);
}

static int32_t KCTBRStateCode(NSString *state) {
  if ([state isEqualToString:@"idle"])
    return 0;
  if ([state isEqualToString:@"running"])
    return 1;
  if ([state isEqualToString:@"route_held"])
    return 2;
  return -1;
}

static int32_t KCTBRErrorCode(NSString *error) {
  if (error == nil)
    return 0;
  if ([error isEqualToString:@"invalid_request"])
    return 1;
  if ([error isEqualToString:@"unavailable"])
    return 2;
  if ([error isEqualToString:@"already_running"])
    return 3;
  if ([error isEqualToString:@"ownership_mismatch"])
    return 4;
  if ([error isEqualToString:@"stale_generation"])
    return 5;
  if ([error isEqualToString:@"route_held"])
    return 6;
  if ([error isEqualToString:@"hold_mismatch"])
    return 7;
  if ([error isEqualToString:@"launch_failed"])
    return 8;
  return -1;
}

static KCTBRClientReply KCTBRFailure(KCTBRTransportStatus status) {
  KCTBRClientReply reply = {
      .transport_status = status,
      .protocol_version = -1,
      .broker_protocol_version = -1,
      .state = -1,
      .error_code = -1,
      .broker_generation = 0,
      .sidecar_instance_id = {0},
      .route_lease_id = {0},
      .operation_id = {0},
  };
  return reply;
}

@interface KCTBRRequest : NSObject
@property(nonatomic, readonly) KCTunnelRouteBindingV3 *binding;
- (instancetype)initWithBinding:(KCTunnelRouteBindingV3 *)binding;
- (BOOL)complete:(KCTBRClientReply)reply;
- (BOOL)waitNanoseconds:(int64_t)nanoseconds;
- (KCTBRClientReply)result;
@end

@implementation KCTBRRequest {
  NSLock *_lock;
  dispatch_semaphore_t _semaphore;
  BOOL _completed;
  KCTBRClientReply _result;
  KCTunnelRouteBindingV3 *_binding;
}
- (instancetype)initWithBinding:(KCTunnelRouteBindingV3 *)binding {
  if ((self = [super init])) {
    _lock = [[NSLock alloc] init];
    _semaphore = dispatch_semaphore_create(0);
    _result = KCTBRFailure(KCTBRTransportTerminal);
    _binding = binding;
  }
  return self;
}
- (KCTunnelRouteBindingV3 *)binding {
  return _binding;
}
- (BOOL)complete:(KCTBRClientReply)reply {
  [_lock lock];
  if (_completed) {
    [_lock unlock];
    return NO;
  }
  _completed = YES;
  _result = reply;
  [_lock unlock];
  dispatch_semaphore_signal(_semaphore);
  return YES;
}
- (BOOL)waitNanoseconds:(int64_t)nanoseconds {
  return dispatch_semaphore_wait(
             _semaphore,
             dispatch_time(DISPATCH_TIME_NOW, nanoseconds)) == 0;
}
- (KCTBRClientReply)result {
  [_lock lock];
  KCTBRClientReply result = _result;
  [_lock unlock];
  return result;
}
@end

@interface KCTBRClient : NSObject {
  NSLock *_stateLock;
  KCTBRRequest *_pending;
  BOOL _terminal;
  KCTBRTransportStatus _terminalStatus;
}
@property(nonatomic, readonly) NSXPCConnection *connection;
- (KCTBRRequest *)begin:(KCTunnelRouteBindingV3 *)binding
        rejectedStatus:(KCTBRTransportStatus *)rejected;
- (void)finish:(KCTBRRequest *)request
          reply:(KCTunnelBrokerRouteReplyV3 *)reply;
- (void)terminalize:(KCTBRTransportStatus)status;
- (void)close;
@end

static NSXPCInterface *KCTBRInterface(void) {
  NSXPCInterface *interface = [NSXPCInterface
      interfaceWithProtocol:@protocol(KCTunnelBrokerRouteV3Protocol)];
  NSSet *binding =
      [NSSet setWithObjects:KCTunnelRouteBindingV3.class, NSString.class, nil];
  NSSet *reply = [NSSet setWithObjects:KCTunnelBrokerRouteReplyV3.class,
                                      NSString.class, nil];
  for (NSString *name in @[ @"holdV3:reply:", @"releaseV3:reply:",
                           @"statusV3:reply:" ]) {
    SEL selector = NSSelectorFromString(name);
    [interface setClasses:binding
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

@implementation KCTBRClient
- (instancetype)init {
  if ((self = [super init])) {
    _stateLock = [[NSLock alloc] init];
    _terminalStatus = KCTBRTransportTerminal;
    _connection = [[NSXPCConnection alloc]
        initWithMachServiceName:KCTBRMachService
                        options:NSXPCConnectionPrivileged];
    _connection.remoteObjectInterface = KCTBRInterface();
    __weak KCTBRClient *weakSelf = self;
    _connection.interruptionHandler = ^{
      [weakSelf terminalize:KCTBRTransportInterrupted];
    };
    _connection.invalidationHandler = ^{
      [weakSelf terminalize:KCTBRTransportInvalidated];
    };
    [_connection resume];
  }
  return self;
}
- (KCTBRRequest *)begin:(KCTunnelRouteBindingV3 *)binding
        rejectedStatus:(KCTBRTransportStatus *)rejected {
  [_stateLock lock];
  if (_terminal || _pending != nil) {
    if (rejected != NULL)
      *rejected = _terminal ? _terminalStatus : KCTBRTransportProtocolFailure;
    [_stateLock unlock];
    return nil;
  }
  KCTBRRequest *request = [[KCTBRRequest alloc] initWithBinding:binding];
  _pending = request;
  [_stateLock unlock];
  return request;
}
- (void)finish:(KCTBRRequest *)request
          reply:(KCTunnelBrokerRouteReplyV3 *)reply {
  [_stateLock lock];
  if (_terminal || _pending != request) {
    [_stateLock unlock];
    return;
  }
  if (reply == nil) {
    [_stateLock unlock];
    [self terminalize:KCTBRTransportProtocolFailure];
    return;
  }
  KCTunnelRouteBindingV3 *expected = request.binding;
  int32_t state = KCTBRStateCode(reply.state);
  int32_t error = KCTBRErrorCode(reply.errorCode);
  BOOL valid = reply.protocolVersion == KCTBRRouteProtocolVersion &&
               reply.brokerProtocolVersion == KCTBRBrokerProtocolVersion &&
               state >= 0 && error >= 0 && reply.brokerGeneration == expected.brokerGeneration &&
               [reply.sidecarInstanceID isEqualToString:expected.sidecarInstanceID] &&
               [reply.routeLeaseID isEqualToString:expected.routeLeaseID] &&
               [reply.operationID isEqualToString:expected.operationID];
  if (!valid) {
    [_stateLock unlock];
    [self terminalize:KCTBRTransportProtocolFailure];
    return;
  }
  KCTBRClientReply result = {
      .transport_status = KCTBRTransportOK,
      .protocol_version = reply.protocolVersion,
      .broker_protocol_version = reply.brokerProtocolVersion,
      .state = state,
      .error_code = error,
      .broker_generation = reply.brokerGeneration,
      .sidecar_instance_id = {0},
      .route_lease_id = {0},
      .operation_id = {0},
  };
  NSData *sidecar = [reply.sidecarInstanceID dataUsingEncoding:NSUTF8StringEncoding];
  NSData *lease = [reply.routeLeaseID dataUsingEncoding:NSUTF8StringEncoding];
  NSData *operation = [reply.operationID dataUsingEncoding:NSUTF8StringEncoding];
  if (sidecar == nil || lease == nil || operation == nil ||
      sidecar.length > KCTBRMaximumIdentifierBytes ||
      lease.length > KCTBRMaximumIdentifierBytes ||
      operation.length > KCTBRMaximumIdentifierBytes) {
    [_stateLock unlock];
    [self terminalize:KCTBRTransportProtocolFailure];
    return;
  }
  memcpy(result.sidecar_instance_id, sidecar.bytes, sidecar.length);
  memcpy(result.route_lease_id, lease.bytes, lease.length);
  memcpy(result.operation_id, operation.bytes, operation.length);
  _pending = nil;
  [request complete:result];
  [_stateLock unlock];
}
- (void)terminalize:(KCTBRTransportStatus)status {
  if (status == KCTBRTransportOK)
    status = KCTBRTransportTerminal;
  [_stateLock lock];
  if (_terminal) {
    [_stateLock unlock];
    return;
  }
  _terminal = YES;
  _terminalStatus = status;
  KCTBRRequest *pending = _pending;
  _pending = nil;
  [pending complete:KCTBRFailure(status)];
  [_stateLock unlock];
}
- (void)close {
  [self terminalize:KCTBRTransportInvalidated];
  [_connection invalidate];
}
- (void)dealloc {
  [self close];
}
@end

typedef NS_ENUM(int32_t, KCTBRMethod) {
  KCTBRMethodHold = 0,
  KCTBRMethodRelease = 1,
  KCTBRMethodStatus = 2,
};

static KCTBRClientReply KCTBRWait(
    KCTBRClient *client, KCTBRMethod method, KCTunnelRouteBindingV3 *binding) {
  if (client == nil || !KCTBRValidBinding(binding))
    return KCTBRFailure(KCTBRTransportInvalidArgument);
  KCTBRTransportStatus rejected = KCTBRTransportTerminal;
  KCTBRRequest *request = [client begin:binding rejectedStatus:&rejected];
  if (request == nil)
    return KCTBRFailure(rejected);
  __weak KCTBRClient *weakClient = client;
  id<KCTunnelBrokerRouteV3Protocol> proxy = [client.connection
      remoteObjectProxyWithErrorHandler:^(__unused NSError *error) {
        [weakClient terminalize:KCTBRTransportRemoteFailure];
      }];
  void (^replyBlock)(KCTunnelBrokerRouteReplyV3 *) =
      ^(KCTunnelBrokerRouteReplyV3 *reply) {
        [client finish:request reply:reply];
      };
  switch (method) {
  case KCTBRMethodHold:
    [proxy holdV3:binding reply:replyBlock];
    break;
  case KCTBRMethodRelease:
    [proxy releaseV3:binding reply:replyBlock];
    break;
  case KCTBRMethodStatus:
    [proxy statusV3:binding reply:replyBlock];
    break;
  }
  if (![request waitNanoseconds:KCTBRTimeoutNanoseconds])
    [client terminalize:KCTBRTransportTimeout];
  return [request result];
}

static NSString *KCTBRString(const char *value) {
  if (value == NULL)
    return nil;
  size_t length = strnlen(value, KCTBRMaximumIdentifierBytes + 1);
  if (length < 8 || length > KCTBRMaximumIdentifierBytes)
    return nil;
  return [[NSString alloc] initWithBytes:value
                                 length:length
                               encoding:NSUTF8StringEncoding];
}

static KCTunnelRouteBindingV3 *KCTBRBinding(int32_t routeVersion,
                                             int32_t brokerVersion,
                                             uint64_t generation,
                                             const char *sidecar,
                                             const char *lease,
                                             const char *operation) {
  NSString *sidecarString = KCTBRString(sidecar);
  NSString *leaseString = KCTBRString(lease);
  NSString *operationString = KCTBRString(operation);
  if (routeVersion < 0 || routeVersion > UINT8_MAX || brokerVersion < 0 ||
      brokerVersion > UINT8_MAX || generation == 0 ||
      generation > INT64_MAX || sidecarString == nil || leaseString == nil ||
      operationString == nil)
    return nil;
  return [[KCTunnelRouteBindingV3 alloc]
      initWithProtocolVersion:(uint8_t)routeVersion
        brokerProtocolVersion:(uint8_t)brokerVersion
              brokerGeneration:generation
             sidecarInstanceID:sidecarString
                  routeLeaseID:leaseString
                   operationID:operationString];
}

void *kyclash_tunnel_broker_route_client_create(void) {
  return (__bridge_retained void *)[[KCTBRClient alloc] init];
}

void kyclash_tunnel_broker_route_client_destroy(void *raw) {
  if (raw != NULL) {
    KCTBRClient *client = CFBridgingRelease(raw);
    [client close];
  }
}

#define KCTBR_ROUTE_CALL(NAME, METHOD)                                      \
  KCTBRClientReply NAME(void *raw, int32_t routeVersion,                    \
                        int32_t brokerVersion, uint64_t generation,         \
                        const char *sidecar, const char *lease,             \
                        const char *operation) {                             \
    KCTBRClient *client = (__bridge KCTBRClient *)raw;                       \
    KCTunnelRouteBindingV3 *binding =                                       \
        KCTBRBinding(routeVersion, brokerVersion, generation, sidecar,       \
                     lease, operation);                                     \
    if (binding == nil)                                                      \
      return KCTBRFailure(KCTBRTransportInvalidArgument);                    \
    return KCTBRWait(client, METHOD, binding);                               \
  }

KCTBR_ROUTE_CALL(kyclash_tunnel_broker_route_client_hold, KCTBRMethodHold)
KCTBR_ROUTE_CALL(kyclash_tunnel_broker_route_client_release,
                 KCTBRMethodRelease)
KCTBR_ROUTE_CALL(kyclash_tunnel_broker_route_client_status, KCTBRMethodStatus)
