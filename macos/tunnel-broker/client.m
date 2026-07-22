#import <Foundation/Foundation.h>

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static NSString *const KCTBMachService = @"net.kysion.kyclash.tunnel-broker";
static const int64_t KCTBTimeoutNanoseconds = 5LL * NSEC_PER_SEC;
static const uint8_t KCTBProtocolVersion = 1;
static const uintptr_t KCTBMaximumIdentifierBytes = 64;

typedef struct {
  int32_t transport_status;
  int32_t protocol_version;
  int32_t state;
  int32_t error_code;
  uint64_t broker_generation;
  int32_t input_fd;
  int32_t output_fd;
  char sidecar_instance_id[65];
} KCTBClientReply;

// Keep this stable: the Rust bridge treats every non-zero transport status as
// terminal for this exact NSXPC generation and never reuses the connection.
typedef NS_ENUM(int32_t, KCTBTransportStatus) {
  KCTBTransportOK = 0,
  KCTBTransportTimeout = 1,
  KCTBTransportRemoteFailure = 2,
  KCTBTransportInterrupted = 3,
  KCTBTransportInvalidated = 4,
  KCTBTransportProtocolFailure = 5,
  KCTBTransportTerminal = 6,
  KCTBTransportInvalidArgument = 7,
};

@interface KCTunnelReference : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t protocolVersion;
@property(nonatomic, readonly) uint64_t generation;
@property(nonatomic, copy, readonly) NSString *sidecarInstanceID;
- (instancetype)initWithProtocolVersion:(uint8_t)protocolVersion
                             generation:(uint64_t)generation
                      sidecarInstanceID:(NSString *)sidecarInstanceID;
@end

@implementation KCTunnelReference
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithProtocolVersion:(uint8_t)protocolVersion
                             generation:(uint64_t)generation
                      sidecarInstanceID:(NSString *)sidecarInstanceID {
  if (sidecarInstanceID == nil)
    return nil;
  if ((self = [super init])) {
    _protocolVersion = protocolVersion;
    _generation = generation;
    _sidecarInstanceID = [sidecarInstanceID copy];
  }
  return self;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"] ||
      ![coder containsValueForKey:@"generation"])
    return nil;
  NSInteger rawVersion = [coder decodeIntegerForKey:@"protocolVersion"];
  int64_t rawGeneration = [coder decodeInt64ForKey:@"generation"];
  NSString *sidecarInstanceID =
      [coder decodeObjectOfClass:NSString.class forKey:@"sidecarInstanceID"];
  if (rawVersion < 0 || rawVersion > UINT8_MAX || rawGeneration <= 0 ||
      sidecarInstanceID == nil)
    return nil;
  return [self initWithProtocolVersion:(uint8_t)rawVersion
                            generation:(uint64_t)rawGeneration
                     sidecarInstanceID:sidecarInstanceID];
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_protocolVersion forKey:@"protocolVersion"];
  [coder encodeInt64:(int64_t)_generation forKey:@"generation"];
  [coder encodeObject:_sidecarInstanceID forKey:@"sidecarInstanceID"];
}
@end

@interface KCTunnelBrokerReply : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t protocolVersion;
@property(nonatomic, copy, readonly) NSString *state;
@property(nonatomic, copy, readonly, nullable) NSString *errorCode;
@end

@implementation KCTunnelBrokerReply
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"])
    return nil;
  NSInteger rawVersion = [coder decodeIntegerForKey:@"protocolVersion"];
  NSString *state = [coder decodeObjectOfClass:NSString.class forKey:@"state"];
  NSString *errorCode =
      [coder decodeObjectOfClass:NSString.class forKey:@"errorCode"];
  if (rawVersion < 0 || rawVersion > UINT8_MAX || state == nil)
    return nil;
  if ((self = [super init])) {
    _protocolVersion = (uint8_t)rawVersion;
    _state = [state copy];
    _errorCode = [errorCode copy];
  }
  return self;
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_protocolVersion forKey:@"protocolVersion"];
  [coder encodeObject:_state forKey:@"state"];
  if (_errorCode != nil)
    [coder encodeObject:_errorCode forKey:@"errorCode"];
}
@end

@interface KCTunnelSessionReply : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t protocolVersion;
@property(nonatomic, copy, readonly) NSString *state;
@property(nonatomic, copy, readonly, nullable) NSString *errorCode;
@property(nonatomic, readonly, nullable) KCTunnelReference *reference;
@property(nonatomic, readonly, nullable) NSFileHandle *inputHandle;
@property(nonatomic, readonly, nullable) NSFileHandle *outputHandle;
@end

@implementation KCTunnelSessionReply
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"])
    return nil;
  NSInteger rawVersion = [coder decodeIntegerForKey:@"protocolVersion"];
  NSString *state = [coder decodeObjectOfClass:NSString.class forKey:@"state"];
  NSString *errorCode =
      [coder decodeObjectOfClass:NSString.class forKey:@"errorCode"];
  if (rawVersion < 0 || rawVersion > UINT8_MAX || state == nil)
    return nil;
  if ((self = [super init])) {
    _protocolVersion = (uint8_t)rawVersion;
    _state = [state copy];
    _errorCode = [errorCode copy];
    _reference =
        [coder decodeObjectOfClass:KCTunnelReference.class forKey:@"reference"];
    _inputHandle =
        [coder decodeObjectOfClass:NSFileHandle.class forKey:@"inputHandle"];
    _outputHandle =
        [coder decodeObjectOfClass:NSFileHandle.class forKey:@"outputHandle"];
  }
  return self;
}
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_protocolVersion forKey:@"protocolVersion"];
  [coder encodeObject:_state forKey:@"state"];
  if (_errorCode != nil)
    [coder encodeObject:_errorCode forKey:@"errorCode"];
  if (_reference != nil)
    [coder encodeObject:_reference forKey:@"reference"];
  if (_inputHandle != nil)
    [coder encodeObject:_inputHandle forKey:@"inputHandle"];
  if (_outputHandle != nil)
    [coder encodeObject:_outputHandle forKey:@"outputHandle"];
}
@end

@protocol KCTunnelBrokerAppProtocol
- (void)startWithReply:(void (^)(KCTunnelSessionReply *))reply;
- (void)stop:(KCTunnelReference *)reference
       reply:(void (^)(KCTunnelBrokerReply *))reply;
- (void)status:(KCTunnelReference *)reference
         reply:(void (^)(KCTunnelBrokerReply *))reply;
@end

static BOOL KCTBValidIdentifier(NSString *value) {
  if (value == nil)
    return NO;
  NSData *encoded = [value dataUsingEncoding:NSUTF8StringEncoding];
  if (encoded == nil || encoded.length < 8 ||
      encoded.length > KCTBMaximumIdentifierBytes)
    return NO;
  const uint8_t *bytes = encoded.bytes;
  for (NSUInteger index = 0; index < encoded.length; index++) {
    uint8_t byte = bytes[index];
    BOOL allowed = (byte >= '0' && byte <= '9') ||
                   (byte >= 'A' && byte <= 'Z') ||
                   (byte >= 'a' && byte <= 'z') || byte == '-' ||
                   byte == '.' || byte == '_';
    if (!allowed)
      return NO;
  }
  return YES;
}

static BOOL KCTBValidReference(KCTunnelReference *reference) {
  return reference != nil &&
         reference.protocolVersion == KCTBProtocolVersion &&
         reference.generation > 0 && reference.generation <= INT64_MAX &&
         KCTBValidIdentifier(reference.sidecarInstanceID);
}

static int32_t KCTBStateCode(NSString *state) {
  if ([state isEqualToString:@"idle"])
    return 0;
  if ([state isEqualToString:@"running"])
    return 1;
  if ([state isEqualToString:@"route_held"])
    return 2;
  return -1;
}

static int32_t KCTBErrorCode(NSString *error) {
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

static KCTBClientReply KCTBFailureForTransport(KCTBTransportStatus status) {
  KCTBClientReply reply = {
      .transport_status = status,
      .protocol_version = -1,
      .state = -1,
      .error_code = -1,
      .broker_generation = 0,
      .input_fd = -1,
      .output_fd = -1,
      .sidecar_instance_id = {0},
  };
  return reply;
}

@interface KCTBRequestCompletion : NSObject
- (BOOL)completeWithResult:(KCTBClientReply)result;
- (BOOL)waitForNanoseconds:(int64_t)nanoseconds;
- (KCTBClientReply)result;
@end

@implementation KCTBRequestCompletion {
  NSLock *_lock;
  dispatch_semaphore_t _semaphore;
  BOOL _completed;
  KCTBClientReply _result;
}
- (instancetype)init {
  if ((self = [super init])) {
    _lock = [[NSLock alloc] init];
    _semaphore = dispatch_semaphore_create(0);
    _completed = NO;
    _result = KCTBFailureForTransport(KCTBTransportTerminal);
  }
  return self;
}
- (BOOL)completeWithResult:(KCTBClientReply)result {
  [_lock lock];
  if (_completed) {
    [_lock unlock];
    if (result.input_fd >= 0)
      close(result.input_fd);
    if (result.output_fd >= 0)
      close(result.output_fd);
    return NO;
  }
  _completed = YES;
  _result = result;
  [_lock unlock];
  dispatch_semaphore_signal(_semaphore);
  return YES;
}
- (BOOL)waitForNanoseconds:(int64_t)nanoseconds {
  return dispatch_semaphore_wait(
             _semaphore,
             dispatch_time(DISPATCH_TIME_NOW, nanoseconds)) == 0;
}
- (KCTBClientReply)result {
  [_lock lock];
  KCTBClientReply result = _result;
  [_lock unlock];
  return result;
}
@end

@interface KCTBClient : NSObject {
  NSLock *_stateLock;
  KCTBRequestCompletion *_pending;
  KCTunnelReference *_reference;
  BOOL _terminal;
  KCTBTransportStatus _terminalStatus;
}
@property(nonatomic, readonly) NSXPCConnection *connection;
- (KCTBRequestCompletion *)beginRequestWithRejectedStatus:
    (KCTBTransportStatus *)rejectedStatus;
- (void)finishSessionRequest:(KCTBRequestCompletion *)request
                       reply:(KCTunnelSessionReply *)reply;
- (void)finishBrokerRequest:(KCTBRequestCompletion *)request
                       reply:(KCTunnelBrokerReply *)reply;
- (KCTunnelReference *)sessionReference;
- (void)clearSessionReference;
- (void)terminalize:(KCTBTransportStatus)status;
- (void)close;
@end

static NSXPCInterface *KCTBClientInterface(void) {
  NSXPCInterface *interface = [NSXPCInterface
      interfaceWithProtocol:@protocol(KCTunnelBrokerAppProtocol)];
  NSSet *session =
      [NSSet setWithObjects:KCTunnelSessionReply.class,
                            KCTunnelReference.class, NSFileHandle.class,
                            NSString.class, nil];
  NSSet *reference =
      [NSSet setWithObjects:KCTunnelReference.class, NSString.class, nil];
  NSSet *reply =
      [NSSet setWithObjects:KCTunnelBrokerReply.class, NSString.class, nil];
  [interface setClasses:session
            forSelector:@selector(startWithReply:)
          argumentIndex:0
                ofReply:YES];
  for (NSString *selectorName in @[ @"stop:reply:", @"status:reply:" ]) {
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

@implementation KCTBClient
- (instancetype)init {
  if ((self = [super init])) {
    _stateLock = [[NSLock alloc] init];
    _terminal = NO;
    _terminalStatus = KCTBTransportTerminal;
    _connection = [[NSXPCConnection alloc]
        initWithMachServiceName:KCTBMachService
                        options:NSXPCConnectionPrivileged];
    _connection.remoteObjectInterface = KCTBClientInterface();
    __weak KCTBClient *weakSelf = self;
    _connection.interruptionHandler = ^{
      [weakSelf terminalize:KCTBTransportInterrupted];
    };
    _connection.invalidationHandler = ^{
      [weakSelf terminalize:KCTBTransportInvalidated];
    };
    [_connection resume];
  }
  return self;
}
- (KCTBRequestCompletion *)beginRequestWithRejectedStatus:
    (KCTBTransportStatus *)rejectedStatus {
  [_stateLock lock];
  if (_terminal || _pending != nil) {
    if (rejectedStatus != NULL)
      *rejectedStatus =
          _terminal ? _terminalStatus : KCTBTransportProtocolFailure;
    [_stateLock unlock];
    return nil;
  }
  KCTBRequestCompletion *request = [[KCTBRequestCompletion alloc] init];
  _pending = request;
  [_stateLock unlock];
  return request;
}
- (void)finishSessionRequest:(KCTBRequestCompletion *)request
                       reply:(KCTunnelSessionReply *)reply {
  [_stateLock lock];
  if (_terminal || _pending != request) {
    // A timed-out/interrupted request can still receive a terminal XPC reply.
    // The Rust side never owns these NSFileHandles because this callback no
    // longer has the pending request. Close them explicitly instead of
    // relying on an autorelease-pool drain as the descriptor-leak boundary.
    if (reply.inputHandle != nil)
      [reply.inputHandle closeFile];
    if (reply.outputHandle != nil)
      [reply.outputHandle closeFile];
    [_stateLock unlock];
    return;
  }
  if (reply == nil) {
    [_stateLock unlock];
    [self terminalize:KCTBTransportProtocolFailure];
    return;
  }
  int32_t state = KCTBStateCode(reply.state);
  int32_t error = KCTBErrorCode(reply.errorCode);
  BOOL baseValid = reply.protocolVersion == KCTBProtocolVersion && state >= 0 &&
                   error >= 0;
  BOOL successfulStart = baseValid && state == 1 && error == 0;
  BOOL payloadValid = !successfulStart ||
                      (KCTBValidReference(reply.reference) &&
                       reply.inputHandle != nil && reply.outputHandle != nil);
  if (!baseValid || !payloadValid) {
    [_stateLock unlock];
    [self terminalize:KCTBTransportProtocolFailure];
    return;
  }

  KCTBClientReply result = {
      .transport_status = KCTBTransportOK,
      .protocol_version = reply.protocolVersion,
      .state = state,
      .error_code = error,
      .broker_generation = 0,
      .input_fd = -1,
      .output_fd = -1,
      .sidecar_instance_id = {0},
  };
  if (successfulStart) {
    int inputFD = fcntl(reply.inputHandle.fileDescriptor, F_DUPFD_CLOEXEC, 0);
    int outputFD = fcntl(reply.outputHandle.fileDescriptor, F_DUPFD_CLOEXEC, 0);
    NSData *identifier =
        [reply.reference.sidecarInstanceID dataUsingEncoding:NSUTF8StringEncoding];
    if (inputFD < 0 || outputFD < 0 || identifier == nil ||
        identifier.length > KCTBMaximumIdentifierBytes) {
      if (inputFD >= 0)
        close(inputFD);
      if (outputFD >= 0)
        close(outputFD);
      [_stateLock unlock];
      [self terminalize:KCTBTransportRemoteFailure];
      return;
    }
    result.broker_generation = reply.reference.generation;
    result.input_fd = inputFD;
    result.output_fd = outputFD;
    memcpy(result.sidecar_instance_id, identifier.bytes, identifier.length);
    result.sidecar_instance_id[identifier.length] = '\0';
    _reference = reply.reference;
  }
  _pending = nil;
  [request completeWithResult:result];
  [_stateLock unlock];
}
- (void)finishBrokerRequest:(KCTBRequestCompletion *)request
                       reply:(KCTunnelBrokerReply *)reply {
  [_stateLock lock];
  if (_terminal || _pending != request) {
    [_stateLock unlock];
    return;
  }
  if (reply == nil) {
    [_stateLock unlock];
    [self terminalize:KCTBTransportProtocolFailure];
    return;
  }
  int32_t state = KCTBStateCode(reply.state);
  int32_t error = KCTBErrorCode(reply.errorCode);
  if (reply.protocolVersion != KCTBProtocolVersion || state < 0 ||
      error < 0) {
    [_stateLock unlock];
    [self terminalize:KCTBTransportProtocolFailure];
    return;
  }
  KCTBClientReply result = {
      .transport_status = KCTBTransportOK,
      .protocol_version = reply.protocolVersion,
      .state = state,
      .error_code = error,
      .broker_generation = _reference.generation,
      .input_fd = -1,
      .output_fd = -1,
      .sidecar_instance_id = {0},
  };
  _pending = nil;
  [request completeWithResult:result];
  [_stateLock unlock];
}
- (KCTunnelReference *)sessionReference {
  [_stateLock lock];
  KCTunnelReference *reference = _reference;
  [_stateLock unlock];
  return reference;
}
- (void)clearSessionReference {
  [_stateLock lock];
  _reference = nil;
  [_stateLock unlock];
}
- (void)terminalize:(KCTBTransportStatus)status {
  if (status == KCTBTransportOK)
    status = KCTBTransportTerminal;
  [_stateLock lock];
  if (_terminal) {
    [_stateLock unlock];
    return;
  }
  _terminal = YES;
  _terminalStatus = status;
  KCTBRequestCompletion *pending = _pending;
  _pending = nil;
  [pending completeWithResult:KCTBFailureForTransport(status)];
  [_stateLock unlock];
}
- (void)close {
  [self terminalize:KCTBTransportInvalidated];
  [_connection invalidate];
}
- (void)dealloc {
  [self close];
}
@end

static KCTBClientReply KCTBWait(
    KCTBClient *client,
    void (^invoke)(id<KCTunnelBrokerAppProtocol>, KCTBRequestCompletion *)) {
  if (client == nil)
    return KCTBFailureForTransport(KCTBTransportInvalidArgument);
  KCTBTransportStatus rejected = KCTBTransportTerminal;
  KCTBRequestCompletion *request =
      [client beginRequestWithRejectedStatus:&rejected];
  if (request == nil)
    return KCTBFailureForTransport(rejected);

  __weak KCTBClient *weakClient = client;
  id<KCTunnelBrokerAppProtocol> proxy = [client.connection
      remoteObjectProxyWithErrorHandler:^(__unused NSError *error) {
        [weakClient terminalize:KCTBTransportRemoteFailure];
      }];
  invoke(proxy, request);
  if (![request waitForNanoseconds:KCTBTimeoutNanoseconds])
    [client terminalize:KCTBTransportTimeout];
  return [request result];
}

void *kyclash_tunnel_broker_client_create(void) {
  return (__bridge_retained void *)[[KCTBClient alloc] init];
}

void kyclash_tunnel_broker_client_destroy(void *raw) {
  if (raw != NULL) {
    KCTBClient *client = CFBridgingRelease(raw);
    [client close];
  }
}

KCTBClientReply kyclash_tunnel_broker_client_start(void *raw) {
  KCTBClient *client = (__bridge KCTBClient *)raw;
  if ([client sessionReference] != nil)
    return KCTBFailureForTransport(KCTBTransportInvalidArgument);
  return KCTBWait(client, ^(id<KCTunnelBrokerAppProtocol> proxy,
                            KCTBRequestCompletion *request) {
    [proxy startWithReply:^(KCTunnelSessionReply *reply) {
      [client finishSessionRequest:request reply:reply];
    }];
  });
}

KCTBClientReply kyclash_tunnel_broker_client_status(void *raw) {
  KCTBClient *client = (__bridge KCTBClient *)raw;
  KCTunnelReference *reference = [client sessionReference];
  if (reference == nil)
    return KCTBFailureForTransport(KCTBTransportInvalidArgument);
  return KCTBWait(client, ^(id<KCTunnelBrokerAppProtocol> proxy,
                            KCTBRequestCompletion *request) {
    [proxy status:reference
            reply:^(KCTunnelBrokerReply *reply) {
              [client finishBrokerRequest:request reply:reply];
            }];
  });
}

KCTBClientReply kyclash_tunnel_broker_client_stop(void *raw) {
  KCTBClient *client = (__bridge KCTBClient *)raw;
  KCTunnelReference *reference = [client sessionReference];
  if (reference == nil)
    return KCTBFailureForTransport(KCTBTransportInvalidArgument);
  KCTBClientReply result =
      KCTBWait(client, ^(id<KCTunnelBrokerAppProtocol> proxy,
                         KCTBRequestCompletion *request) {
        [proxy stop:reference
               reply:^(KCTunnelBrokerReply *reply) {
                 [client finishBrokerRequest:request reply:reply];
               }];
      });
  if (result.transport_status == KCTBTransportOK && result.state == 0 &&
      result.error_code == 0)
    [client clearSessionReference];
  return result;
}
