// Typed route-helper v3 client used by the signed production App/helper path.
//
// This bridge is intentionally independent from client.m.  It speaks only
// the fixed `net.kysion.kyclash.route-helper` Mach service and only the v3
// selectors/classes. It accepts no command, path, shell, or generic
// dictionary.

#import <Foundation/Foundation.h>

#import "client-v3.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

static NSString *const KCRV3MachService =
    @"net.kysion.kyclash.route-helper";
static const int64_t KCRV3TimeoutNanoseconds = 5LL * NSEC_PER_SEC;
static const uint8_t KCRV3ProtocolVersion = 3;
static const uint8_t KCRV3BrokerProtocolVersion = 1;
static const uint64_t KCRV3MaximumGeneration = UINT64_C(0x7fffffffffffffff);
static const size_t KCRV3MaximumIdentifierBytes = 64;
static const size_t KCRV3MaximumMihomoInterfaces = 1;
static const size_t KCRV3MaximumCIDRs = 64;
static const size_t KCRV3MaximumStringBytes = 1024;

static KCRV3ClientReply KCRV3Failure(KCRV3TransportStatus status);

@interface KCRLeaseReferenceV3 : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t protocolVersion;
@property(nonatomic, readonly) uint8_t brokerProtocolVersion;
@property(nonatomic, readonly) uint64_t brokerGeneration;
@property(nonatomic, copy, readonly) NSString *sidecarInstanceID;
@property(nonatomic, copy, readonly) NSString *leaseID;
@property(nonatomic, copy, readonly) NSString *operationID;
- (instancetype)initWithProtocolVersion:(uint8_t)protocolVersion
                   brokerProtocolVersion:(uint8_t)brokerProtocolVersion
                        brokerGeneration:(uint64_t)brokerGeneration
                       sidecarInstanceID:(NSString *)sidecarInstanceID
                                 leaseID:(NSString *)leaseID
                              operationID:(NSString *)operationID;
- (BOOL)isValid;
- (BOOL)matches:(KCRLeaseReferenceV3 *)other;
@end

@interface KCRLeaseOwnerV3 : NSObject <NSSecureCoding>
@property(nonatomic, strong, readonly) KCRLeaseReferenceV3 *reference;
@property(nonatomic, copy, readonly) NSString *sidecarInstanceID;
@property(nonatomic, copy, readonly) NSString *interfaceName;
@property(nonatomic, copy, readonly) NSString *tunnelOperationID;
@property(nonatomic, readonly) uint16_t mtu;
@property(nonatomic, readonly) uint64_t profileRevision;
@property(nonatomic, readonly) BOOL hasIPv4;
@property(nonatomic, readonly) BOOL hasIPv6;
@property(nonatomic, copy, readonly) NSArray<NSString *> *activeMihomoTunInterfaces;
@property(nonatomic, copy, readonly) NSArray<NSString *> *privateCIDRs;
- (instancetype)initWithReference:(KCRLeaseReferenceV3 *)reference
                 sidecarInstanceID:(NSString *)sidecarInstanceID
                      interfaceName:(NSString *)interfaceName
                  tunnelOperationID:(NSString *)tunnelOperationID
                                mtu:(uint16_t)mtu
                    profileRevision:(uint64_t)profileRevision
                          hasIPv4:(BOOL)hasIPv4
                          hasIPv6:(BOOL)hasIPv6
              activeMihomoTunInterfaces:(NSArray<NSString *> *)activeMihomoTunInterfaces
                           privateCIDRs:(NSArray<NSString *> *)privateCIDRs;
- (BOOL)isValid;
@end

@interface KCRReplyV3 : NSObject <NSSecureCoding>
@property(nonatomic, readonly) uint8_t protocolVersion;
@property(nonatomic, copy, readonly) NSString *state;
@property(nonatomic, copy, readonly, nullable) NSString *errorCode;
@property(nonatomic, strong, readonly, nullable) KCRLeaseReferenceV3 *reference;
@property(nonatomic, readonly) uint64_t transition;
- (BOOL)isValid;
@end

@protocol KCRRouteHelperV3Protocol
- (void)discoverV3WithReply:(void (^)(KCRReplyV3 *reply))reply;
- (void)beginV3:(KCRLeaseOwnerV3 *)owner
           reply:(void (^)(KCRReplyV3 *reply))reply;
- (void)applyV3:(KCRLeaseReferenceV3 *)reference
          reply:(void (^)(KCRReplyV3 *reply))reply;
- (void)rollbackV3:(KCRLeaseReferenceV3 *)reference
             reply:(void (^)(KCRReplyV3 *reply))reply;
- (void)recoverV3:(KCRLeaseOwnerV3 *)owner
            reply:(void (^)(KCRReplyV3 *reply))reply;
- (void)heartbeatV3:(KCRLeaseReferenceV3 *)reference
               reply:(void (^)(KCRReplyV3 *reply))reply;
- (void)statusV3:(KCRLeaseReferenceV3 *)reference
           reply:(void (^)(KCRReplyV3 *reply))reply;
@end

static BOOL KCRV3ValidIdentifier(NSString *value) {
  if (value == nil)
    return NO;
  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
  if (data == nil || data.length < 8 || data.length > KCRV3MaximumIdentifierBytes)
    return NO;
  const uint8_t *bytes = data.bytes;
  for (NSUInteger index = 0; index < data.length; index++) {
    uint8_t byte = bytes[index];
    if (!((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
          (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '.' ||
          byte == '_'))
      return NO;
  }
  return YES;
}

static BOOL KCRV3ValidUtun(NSString *value) {
  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
  if (data == nil || data.length < 5 || data.length > 15)
    return NO;
  const uint8_t *bytes = data.bytes;
  if (memcmp(bytes, "utun", 4) != 0)
    return NO;
  if (data.length > 5 && bytes[4] == '0')
    return NO;
  for (NSUInteger index = 4; index < data.length; index++)
    if (bytes[index] < '0' || bytes[index] > '9')
      return NO;
  return YES;
}

typedef struct {
  BOOL ipv4;
  uint8_t length;
  uint8_t prefix;
  uint8_t bytes[16];
} KCRV3Network;

static BOOL KCRV3NetworksOverlap(const KCRV3Network *lhs,
                                 const KCRV3Network *rhs) {
  if (lhs == NULL || rhs == NULL || lhs->ipv4 != rhs->ipv4 ||
      lhs->length != rhs->length)
    return NO;
  NSUInteger remaining = MIN(lhs->prefix, rhs->prefix);
  NSUInteger index = 0;
  while (remaining > 0) {
    NSUInteger comparedBits = MIN(remaining, (NSUInteger)8);
    uint8_t mask = comparedBits == 8 ? UINT8_MAX
                                     : (uint8_t)(UINT8_MAX << (8 - comparedBits));
    if ((lhs->bytes[index] & mask) != (rhs->bytes[index] & mask))
      return NO;
    remaining -= comparedBits;
    index += 1;
  }
  return YES;
}

// Keep C-side validation equivalent to Swift validCIDR: only canonical,
// non-default, non-multicast private route networks are accepted.  This is a
// bounded parser; no caller-controlled command or path is interpreted here.
static BOOL KCRV3ParseCIDR(NSString *value, KCRV3Network *network) {
  if (![value isKindOfClass:NSString.class])
    return NO;
  NSData *encoded = [value dataUsingEncoding:NSUTF8StringEncoding];
  if (encoded == nil || encoded.length == 0 ||
      encoded.length > KCRV3MaximumStringBytes ||
      memchr(encoded.bytes, 0, encoded.length) != NULL)
    return NO;
  const uint8_t *encodedBytes = encoded.bytes;
  for (NSUInteger index = 0; index < encoded.length; index++) {
    uint8_t byte = encodedBytes[index];
    if (byte == '%' || byte == '\n' || byte == '\r' || byte == '\t' ||
        byte == ' ')
      return NO;
  }

  NSArray<NSString *> *parts = [value componentsSeparatedByString:@"/"];
  if (parts.count != 2 || parts[0].length == 0 || parts[1].length == 0)
    return NO;
  NSData *prefixData = [parts[1] dataUsingEncoding:NSUTF8StringEncoding];
  if (prefixData == nil || prefixData.length == 0 || prefixData.length > 3)
    return NO;
  const uint8_t *prefixBytes = prefixData.bytes;
  if (prefixData.length > 1 && prefixBytes[0] == '0')
    return NO;
  unsigned prefix = 0;
  for (NSUInteger index = 0; index < prefixData.length; index++) {
    if (prefixBytes[index] < '0' || prefixBytes[index] > '9')
      return NO;
    prefix = prefix * 10u + (unsigned)(prefixBytes[index] - '0');
  }
  if (prefix == 0 || prefix > 128)
    return NO;

  const char *address = parts[0].UTF8String;
  if (address == NULL)
    return NO;
  KCRV3Network parsed = {0};
  struct in_addr address4;
  struct in6_addr address6;
  BOOL hasColon = [parts[0] rangeOfString:@":"].location != NSNotFound;
  if (!hasColon) {
    if (inet_pton(AF_INET, address, &address4) != 1 || prefix > 32)
      return NO;
    parsed.ipv4 = YES;
    parsed.length = 4;
    parsed.prefix = (uint8_t)prefix;
    memcpy(parsed.bytes, &address4, 4);
  } else {
    if (inet_pton(AF_INET6, address, &address6) != 1)
      return NO;
    parsed.ipv4 = NO;
    parsed.length = 16;
    parsed.prefix = (uint8_t)prefix;
    memcpy(parsed.bytes, &address6, 16);
  }

  uint8_t canonical[16] = {0};
  memcpy(canonical, parsed.bytes, parsed.length);
  NSUInteger fullBytes = parsed.prefix / 8;
  NSUInteger remainder = parsed.prefix % 8;
  if (remainder != 0) {
    canonical[fullBytes] &= (uint8_t)(UINT8_MAX << (8 - remainder));
    fullBytes += 1;
  }
  for (NSUInteger index = fullBytes; index < parsed.length; index++)
    canonical[index] = 0;
  if (memcmp(canonical, parsed.bytes, parsed.length) != 0)
    return NO;

  BOOL allZero = YES;
  for (NSUInteger index = 0; index < parsed.length; index++)
    allZero = allZero && parsed.bytes[index] == 0;
  BOOL multicast = parsed.ipv4 ? parsed.bytes[0] >= 224 : parsed.bytes[0] == 0xff;
  if (allZero || multicast)
    return NO;

  char canonicalAddress[INET6_ADDRSTRLEN] = {0};
  int family = parsed.ipv4 ? AF_INET : AF_INET6;
  if (inet_ntop(family, parsed.bytes, canonicalAddress,
                sizeof(canonicalAddress)) == NULL)
    return NO;
  NSString *canonicalAddressString =
      [NSString stringWithUTF8String:canonicalAddress];
  NSString *canonicalPrefix = [NSString stringWithFormat:@"%u", prefix];
  if (canonicalAddressString == nil ||
      ![parts[0] isEqualToString:canonicalAddressString] ||
      ![parts[1] isEqualToString:canonicalPrefix])
    return NO;
  if (network != NULL)
    *network = parsed;
  return YES;
}

static BOOL KCRV3CIDRsAreDisjoint(NSArray<NSString *> *values) {
  for (NSUInteger index = 0; index < values.count; index++) {
    KCRV3Network current;
    if (!KCRV3ParseCIDR(values[index], &current))
      return NO;
    for (NSUInteger otherIndex = index + 1; otherIndex < values.count;
         otherIndex++) {
      KCRV3Network other;
      if (!KCRV3ParseCIDR(values[otherIndex], &other) ||
          KCRV3NetworksOverlap(&current, &other))
        return NO;
    }
  }
  return YES;
}

static BOOL KCRV3ArrayStrings(NSArray<NSString *> *values, size_t maximum,
                               BOOL requireSortedUnique) {
  if (values == nil || values.count > maximum)
    return NO;
  NSString *previous = nil;
  NSMutableSet<NSString *> *seen = [NSMutableSet setWithCapacity:values.count];
  for (NSString *value in values) {
    NSData *encoded = [value isKindOfClass:NSString.class]
                          ? [value dataUsingEncoding:NSUTF8StringEncoding]
                          : nil;
    if (encoded == nil || encoded.length == 0 ||
        encoded.length > KCRV3MaximumStringBytes ||
        memchr(encoded.bytes, 0, encoded.length) != NULL)
      return NO;
    if (requireSortedUnique) {
      if ([seen containsObject:value] ||
          (previous != nil && [previous compare:value] != NSOrderedAscending))
        return NO;
      [seen addObject:value];
      previous = value;
    }
  }
  return YES;
}

@implementation KCRLeaseReferenceV3
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)initWithProtocolVersion:(uint8_t)protocolVersion
                   brokerProtocolVersion:(uint8_t)brokerProtocolVersion
                        brokerGeneration:(uint64_t)brokerGeneration
                       sidecarInstanceID:(NSString *)sidecarInstanceID
                                 leaseID:(NSString *)leaseID
                              operationID:(NSString *)operationID {
  if ((self = [super init])) {
    _protocolVersion = protocolVersion;
    _brokerProtocolVersion = brokerProtocolVersion;
    _brokerGeneration = brokerGeneration;
    _sidecarInstanceID = [sidecarInstanceID copy];
    _leaseID = [leaseID copy];
    _operationID = [operationID copy];
  }
  return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"] ||
      ![coder containsValueForKey:@"brokerProtocolVersion"] ||
      ![coder containsValueForKey:@"brokerGeneration"])
    return nil;
  NSInteger protocol = [coder decodeIntegerForKey:@"protocolVersion"];
  NSInteger brokerProtocol = [coder decodeIntegerForKey:@"brokerProtocolVersion"];
  int64_t generation = [coder decodeInt64ForKey:@"brokerGeneration"];
  NSString *sidecar = [coder decodeObjectOfClass:NSString.class
                                          forKey:@"sidecarInstanceID"];
  NSString *lease = [coder decodeObjectOfClass:NSString.class forKey:@"leaseID"];
  NSString *operation = [coder decodeObjectOfClass:NSString.class
                                             forKey:@"operationID"];
  if (protocol < 0 || protocol > UINT8_MAX || brokerProtocol < 0 ||
      brokerProtocol > UINT8_MAX || generation <= 0 || sidecar == nil ||
      lease == nil || operation == nil)
    return nil;
  return [self initWithProtocolVersion:(uint8_t)protocol
                  brokerProtocolVersion:(uint8_t)brokerProtocol
                       brokerGeneration:(uint64_t)generation
                      sidecarInstanceID:sidecar
                                leaseID:lease
                             operationID:operation];
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeInteger:_protocolVersion forKey:@"protocolVersion"];
  [coder encodeInteger:_brokerProtocolVersion forKey:@"brokerProtocolVersion"];
  [coder encodeInt64:(int64_t)_brokerGeneration forKey:@"brokerGeneration"];
  [coder encodeObject:_sidecarInstanceID forKey:@"sidecarInstanceID"];
  [coder encodeObject:_leaseID forKey:@"leaseID"];
  [coder encodeObject:_operationID forKey:@"operationID"];
}

- (BOOL)isValid {
  return _protocolVersion == KCRV3ProtocolVersion &&
         _brokerProtocolVersion == KCRV3BrokerProtocolVersion &&
         _brokerGeneration > 0 && _brokerGeneration <= KCRV3MaximumGeneration &&
         KCRV3ValidIdentifier(_sidecarInstanceID) &&
         KCRV3ValidIdentifier(_leaseID) && KCRV3ValidIdentifier(_operationID);
}

- (BOOL)matches:(KCRLeaseReferenceV3 *)other {
  return other != nil && [self isValid] && [other isValid] &&
         _protocolVersion == other.protocolVersion &&
         _brokerProtocolVersion == other.brokerProtocolVersion &&
         _brokerGeneration == other.brokerGeneration &&
         [_sidecarInstanceID isEqualToString:other.sidecarInstanceID] &&
         [_leaseID isEqualToString:other.leaseID] &&
         [_operationID isEqualToString:other.operationID];
}
@end

@implementation KCRLeaseOwnerV3
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)initWithReference:(KCRLeaseReferenceV3 *)reference
                 sidecarInstanceID:(NSString *)sidecarInstanceID
                      interfaceName:(NSString *)interfaceName
                  tunnelOperationID:(NSString *)tunnelOperationID
                                mtu:(uint16_t)mtu
                    profileRevision:(uint64_t)profileRevision
                          hasIPv4:(BOOL)hasIPv4
                          hasIPv6:(BOOL)hasIPv6
              activeMihomoTunInterfaces:(NSArray<NSString *> *)activeMihomoTunInterfaces
                           privateCIDRs:(NSArray<NSString *> *)privateCIDRs {
  if ((self = [super init])) {
    _reference = reference;
    _sidecarInstanceID = [sidecarInstanceID copy];
    _interfaceName = [interfaceName copy];
    _tunnelOperationID = [tunnelOperationID copy];
    _mtu = mtu;
    _profileRevision = profileRevision;
    _hasIPv4 = hasIPv4;
    _hasIPv6 = hasIPv6;
    _activeMihomoTunInterfaces = [activeMihomoTunInterfaces copy];
    _privateCIDRs = [privateCIDRs copy];
  }
  return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
  NSSet *arrayClasses = [NSSet setWithObjects:NSArray.class, NSString.class, nil];
  if (![coder containsValueForKey:@"mtu"] ||
      ![coder containsValueForKey:@"profileRevision"] ||
      ![coder containsValueForKey:@"hasIPv4"] ||
      ![coder containsValueForKey:@"hasIPv6"])
    return nil;
  KCRLeaseReferenceV3 *reference =
      [coder decodeObjectOfClass:KCRLeaseReferenceV3.class forKey:@"reference"];
  NSString *sidecar = [coder decodeObjectOfClass:NSString.class
                                          forKey:@"sidecarInstanceID"];
  NSString *interfaceName = [coder decodeObjectOfClass:NSString.class
                                               forKey:@"interfaceName"];
  NSString *tunnelOperation = [coder decodeObjectOfClass:NSString.class
                                                  forKey:@"tunnelOperationID"];
  NSArray *mihomo = [coder decodeObjectOfClasses:arrayClasses
                                         forKey:@"activeMihomoTunInterfaces"];
  NSArray *cidrs = [coder decodeObjectOfClasses:arrayClasses forKey:@"privateCIDRs"];
  NSInteger mtu = [coder decodeIntegerForKey:@"mtu"];
  int64_t revision = [coder decodeInt64ForKey:@"profileRevision"];
  NSInteger ipv4 = [coder decodeIntegerForKey:@"hasIPv4"];
  NSInteger ipv6 = [coder decodeIntegerForKey:@"hasIPv6"];
  if (reference == nil || sidecar == nil || interfaceName == nil ||
      tunnelOperation == nil || mihomo == nil || cidrs == nil || mtu < 0 ||
      mtu > UINT16_MAX || revision <= 0 || ipv4 < 0 || ipv4 > 1 || ipv6 < 0 ||
      ipv6 > 1)
    return nil;
  return [self initWithReference:reference
                sidecarInstanceID:sidecar
                     interfaceName:interfaceName
                 tunnelOperationID:tunnelOperation
                               mtu:(uint16_t)mtu
                   profileRevision:(uint64_t)revision
                         hasIPv4:(BOOL)ipv4
                         hasIPv6:(BOOL)ipv6
             activeMihomoTunInterfaces:mihomo
                          privateCIDRs:cidrs];
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:_reference forKey:@"reference"];
  [coder encodeObject:_sidecarInstanceID forKey:@"sidecarInstanceID"];
  [coder encodeObject:_interfaceName forKey:@"interfaceName"];
  [coder encodeObject:_tunnelOperationID forKey:@"tunnelOperationID"];
  [coder encodeInteger:_mtu forKey:@"mtu"];
  [coder encodeInt64:(int64_t)_profileRevision forKey:@"profileRevision"];
  [coder encodeInteger:_hasIPv4 ? 1 : 0 forKey:@"hasIPv4"];
  [coder encodeInteger:_hasIPv6 ? 1 : 0 forKey:@"hasIPv6"];
  [coder encodeObject:_activeMihomoTunInterfaces
               forKey:@"activeMihomoTunInterfaces"];
  [coder encodeObject:_privateCIDRs forKey:@"privateCIDRs"];
}

- (BOOL)isValid {
  if (![_reference isValid] ||
      ![_sidecarInstanceID isEqualToString:_reference.sidecarInstanceID] ||
      !KCRV3ValidUtun(_interfaceName) ||
      ![_tunnelOperationID isEqualToString:
          [NSString stringWithFormat:@"%@.prepare", _reference.operationID]] ||
      _mtu != 1420 || _profileRevision == 0 ||
      _profileRevision > KCRV3MaximumGeneration || (!_hasIPv4 && !_hasIPv6) ||
      !KCRV3ArrayStrings(_activeMihomoTunInterfaces,
                         KCRV3MaximumMihomoInterfaces, YES) ||
      !KCRV3ArrayStrings(_privateCIDRs, KCRV3MaximumCIDRs, YES) ||
      _privateCIDRs.count == 0)
    return NO;
  for (NSString *interfaceName in _activeMihomoTunInterfaces)
    if (!KCRV3ValidUtun(interfaceName) ||
        [interfaceName isEqualToString:_interfaceName])
      return NO;
  for (NSString *cidr in _privateCIDRs) {
    KCRV3Network network;
    if (!KCRV3ParseCIDR(cidr, &network) ||
        (network.ipv4 ? !_hasIPv4 : !_hasIPv6))
      return NO;
  }
  if (!KCRV3CIDRsAreDisjoint(_privateCIDRs))
    return NO;
  return YES;
}
@end

@implementation KCRReplyV3
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
  if (![coder containsValueForKey:@"protocolVersion"] ||
      ![coder containsValueForKey:@"transition"])
    return nil;
  NSInteger protocol = [coder decodeIntegerForKey:@"protocolVersion"];
  int64_t transition = [coder decodeInt64ForKey:@"transition"];
  NSString *state = [coder decodeObjectOfClass:NSString.class forKey:@"state"];
  NSString *error = [coder decodeObjectOfClass:NSString.class forKey:@"errorCode"];
  KCRLeaseReferenceV3 *reference =
      [coder decodeObjectOfClass:KCRLeaseReferenceV3.class forKey:@"reference"];
  if (protocol < 0 || protocol > UINT8_MAX || transition < 0 || state == nil)
    return nil;
  if ((self = [super init])) {
    _protocolVersion = (uint8_t)protocol;
    _state = [state copy];
    _errorCode = [error copy];
    _reference = reference;
    _transition = (uint64_t)transition;
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
  [coder encodeInt64:(int64_t)_transition forKey:@"transition"];
}

- (BOOL)isValid {
  NSSet *states = [NSSet setWithObjects:@"idle", @"hold_pending", @"held",
                                         @"applied", @"retirement_pending",
                                         @"released", @"recovery_only",
                                         @"failed_closed", nil];
  NSSet *errors = [NSSet setWithObjects:@"not_ready", @"invalid_owner",
                                        @"permission_denied", @"route_conflict",
                                        @"journal_write_failed",
                                        @"journal_corrupt", @"route_apply_failed",
                                        @"rollback_failed", @"release_failed",
                                        @"recovery_required", @"ownership_mismatch",
                                        @"broker_protocol_failure",
                                        @"broker_status_failed", nil];
  if (_protocolVersion != KCRV3ProtocolVersion || ![states containsObject:_state] ||
      (_errorCode != nil && ![errors containsObject:_errorCode]))
    return NO;
  if (_reference != nil)
    return [_reference isValid] && _transition > 0;
  return _transition == 0 &&
         ([_state isEqualToString:@"idle"] ||
          [_state isEqualToString:@"recovery_only"] ||
          [_state isEqualToString:@"failed_closed"]);
}
@end

@interface KCRV3Request : NSObject
@property(nonatomic, readonly) uint64_t requestID;
@property(nonatomic, strong, readonly, nullable) KCRLeaseReferenceV3 *expectedReference;
@property(nonatomic, readonly) BOOL allowIdleWithoutReference;
- (instancetype)initWithRequestID:(uint64_t)requestID
                 expectedReference:(KCRLeaseReferenceV3 *)expectedReference
           allowIdleWithoutReference:(BOOL)allowIdleWithoutReference;
- (BOOL)completeWithResult:(KCRV3ClientReply)result;
- (BOOL)waitForNanoseconds:(int64_t)nanoseconds;
- (KCRV3ClientReply)result;
@end

@implementation KCRV3Request {
  NSLock *_stateLock;
  dispatch_semaphore_t _semaphore;
  BOOL _completed;
  KCRV3ClientReply _result;
}
- (instancetype)initWithRequestID:(uint64_t)requestID
                 expectedReference:(KCRLeaseReferenceV3 *)expectedReference
           allowIdleWithoutReference:(BOOL)allowIdleWithoutReference {
  if ((self = [super init])) {
    _requestID = requestID;
    _expectedReference = expectedReference;
    _allowIdleWithoutReference = allowIdleWithoutReference;
    _stateLock = [[NSLock alloc] init];
    _semaphore = dispatch_semaphore_create(0);
    _completed = NO;
    _result = KCRV3Failure(KCRV3TransportTerminal);
  }
  return self;
}
- (BOOL)completeWithResult:(KCRV3ClientReply)result {
  [_stateLock lock];
  if (_completed) {
    [_stateLock unlock];
    return NO;
  }
  _completed = YES;
  _result = result;
  [_stateLock unlock];
  dispatch_semaphore_signal(_semaphore);
  return YES;
}
- (BOOL)waitForNanoseconds:(int64_t)nanoseconds {
  return dispatch_semaphore_wait(_semaphore,
                                  dispatch_time(DISPATCH_TIME_NOW, nanoseconds)) == 0;
}
- (KCRV3ClientReply)result {
  [_stateLock lock];
  KCRV3ClientReply result = _result;
  [_stateLock unlock];
  return result;
}
@end

@interface KCRV3Client : NSObject
@property(nonatomic, strong, readonly) NSXPCConnection *connection;
- (void)finishRequest:(KCRV3Request *)request reply:(KCRReplyV3 *)reply;
- (void)terminalize:(KCRV3TransportStatus)status;
- (void)markTransient:(KCRV3TransportStatus)status epoch:(NSUInteger)epoch;
- (BOOL)ensureConnection;
- (KCRV3ClientReply)waitWithExpectedReference:(KCRLeaseReferenceV3 *)expectedReference
                       allowIdleWithoutReference:(BOOL)allowIdleWithoutReference
                                          invoke:(void (^)(id<KCRRouteHelperV3Protocol>, void (^)(KCRReplyV3 *)))invoke;
- (void)close;
@end

static KCRV3ClientReply KCRV3Failure(KCRV3TransportStatus status) {
  return (KCRV3ClientReply){.transport_status = status,
                            .protocol_version = -1,
                            .state = -1,
                            .error_code = -1,
                            .transition = 0,
                            .broker_generation = 0};
}

static int32_t KCRV3StateCode(NSString *state) {
  NSArray<NSString *> *states = @[
    @"idle", @"hold_pending", @"held", @"applied", @"retirement_pending",
    @"released", @"recovery_only", @"failed_closed"
  ];
  NSUInteger index = [states indexOfObject:state];
  return index == NSNotFound ? -1 : (int32_t)index;
}

static int32_t KCRV3ErrorValue(NSString *error) {
  if (error == nil)
    return 0;
  if ([error isEqualToString:@"not_ready"])
    return 1;
  if ([error isEqualToString:@"invalid_owner"])
    return 2;
  if ([error isEqualToString:@"permission_denied"])
    return 3;
  if ([error isEqualToString:@"journal_write_failed"])
    return 4;
  if ([error isEqualToString:@"journal_corrupt"])
    return 5;
  if ([error isEqualToString:@"route_apply_failed"])
    return 6;
  if ([error isEqualToString:@"rollback_failed"] ||
      [error isEqualToString:@"release_failed"])
    return 7;
  if ([error isEqualToString:@"route_conflict"])
    return 8;
  if ([error isEqualToString:@"recovery_required"])
    return 9;
  if ([error isEqualToString:@"ownership_mismatch"])
    return 10;
  if ([error isEqualToString:@"broker_protocol_failure"])
    return 11;
  if ([error isEqualToString:@"broker_status_failed"])
    return 12;
  return -1;
}

static void KCRV3CopyString(char destination[65], NSString *value) {
  memset(destination, 0, 65);
  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
  if (data == nil || data.length > 64)
    return;
  memcpy(destination, data.bytes, data.length);
}

static KCRV3ClientReply KCRV3ReplyValue(KCRReplyV3 *reply,
                                        KCRLeaseReferenceV3 *expected,
                                        BOOL allowIdleWithoutReference) {
  if (reply == nil || ![reply isValid])
    return KCRV3Failure(KCRV3TransportProtocolFailure);
  int32_t state = KCRV3StateCode(reply.state);
  int32_t error = KCRV3ErrorValue(reply.errorCode);
  if (state < 0 || error < 0)
    return KCRV3Failure(KCRV3TransportProtocolFailure);
  if (expected == nil) {
    if (reply.reference != nil)
      return KCRV3Failure(KCRV3TransportProtocolFailure);
  } else if (reply.reference == nil) {
    // rollbackV3 is explicitly idempotent when the journal is already absent;
    // all other mutation replies must echo the complete reference.
    if (!(allowIdleWithoutReference && state == 0 && error == 0))
      return KCRV3Failure(KCRV3TransportProtocolFailure);
  } else if (![reply.reference matches:expected]) {
    return KCRV3Failure(KCRV3TransportProtocolFailure);
  }
  KCRV3ClientReply result = {
    .transport_status = KCRV3TransportOK,
    .protocol_version = reply.protocolVersion,
    .state = state,
    .error_code = error,
    .transition = reply.transition,
    .broker_generation = reply.reference == nil ? 0 : reply.reference.brokerGeneration,
  };
  if (reply.reference != nil) {
    KCRV3CopyString(result.sidecar_instance_id, reply.reference.sidecarInstanceID);
    KCRV3CopyString(result.route_lease_id, reply.reference.leaseID);
    KCRV3CopyString(result.operation_id, reply.reference.operationID);
  }
  return result;
}

@implementation KCRV3Client {
  NSLock *_stateLock;
  NSMutableDictionary<NSNumber *, KCRV3Request *> *_pending;
  uint64_t _nextRequestID;
  BOOL _terminal;
  BOOL _closed;
  BOOL _needsReconnect;
  NSUInteger _connectionEpoch;
  KCRV3TransportStatus _terminalStatus;
}

static NSXPCInterface *KCRV3Interface(void) {
  NSXPCInterface *interface =
      [NSXPCInterface interfaceWithProtocol:@protocol(KCRRouteHelperV3Protocol)];
  NSSet *replyClasses =
      [NSSet setWithObjects:KCRReplyV3.class, KCRLeaseReferenceV3.class,
                            NSString.class, nil];
  NSSet *ownerClasses =
      [NSSet setWithObjects:KCRLeaseOwnerV3.class, KCRLeaseReferenceV3.class,
                            NSArray.class, NSString.class, nil];
  NSSet *referenceClasses =
      [NSSet setWithObjects:KCRLeaseReferenceV3.class, NSString.class, nil];
  SEL discover = @selector(discoverV3WithReply:);
  [interface setClasses:replyClasses forSelector:discover argumentIndex:0 ofReply:YES];
  for (NSString *name in @[ @"beginV3:reply:", @"recoverV3:reply:" ]) {
    SEL selector = NSSelectorFromString(name);
    [interface setClasses:ownerClasses forSelector:selector argumentIndex:0 ofReply:NO];
    [interface setClasses:replyClasses forSelector:selector argumentIndex:0 ofReply:YES];
  }
  for (NSString *name in @[ @"applyV3:reply:", @"rollbackV3:reply:",
                            @"heartbeatV3:reply:", @"statusV3:reply:" ]) {
    SEL selector = NSSelectorFromString(name);
    [interface setClasses:referenceClasses forSelector:selector argumentIndex:0 ofReply:NO];
    [interface setClasses:replyClasses forSelector:selector argumentIndex:0 ofReply:YES];
  }
  return interface;
}

- (BOOL)ensureConnection {
  [_stateLock lock];
  if (_closed) {
    [_stateLock unlock];
    return NO;
  }
  if (_connection != nil && !_needsReconnect) {
    [_stateLock unlock];
    return YES;
  }
  NSUInteger epoch = ++_connectionEpoch;
  NSXPCConnection *connection = [[NSXPCConnection alloc]
      initWithMachServiceName:KCRV3MachService options:NSXPCConnectionPrivileged];
  connection.remoteObjectInterface = KCRV3Interface();
  __weak KCRV3Client *weakSelf = self;
  connection.interruptionHandler = ^{
    [weakSelf markTransient:KCRV3TransportInterrupted epoch:epoch];
  };
  connection.invalidationHandler = ^{
    [weakSelf markTransient:KCRV3TransportInvalidated epoch:epoch];
  };
  _connection = connection;
  _needsReconnect = NO;
  [_stateLock unlock];
  [connection resume];
  return YES;
}

- (instancetype)init {
  if ((self = [super init])) {
    _stateLock = [[NSLock alloc] init];
    _pending = [[NSMutableDictionary alloc] init];
    _nextRequestID = 1;
    _terminal = NO;
    _closed = NO;
    _needsReconnect = YES;
    _terminalStatus = KCRV3TransportTerminal;
    [self ensureConnection];
  }
  return self;
}

- (void)finishRequest:(KCRV3Request *)request reply:(KCRReplyV3 *)reply {
  if (request == nil)
    return;
  [_stateLock lock];
  KCRV3Request *registered = _pending[@(request.requestID)];
  if (_terminal || registered != request) {
    [_stateLock unlock];
    return;
  }
  KCRV3ClientReply result = KCRV3ReplyValue(
      reply, request.expectedReference, request.allowIdleWithoutReference);
  if (result.transport_status != KCRV3TransportOK) {
    _terminal = YES;
    _terminalStatus = KCRV3TransportProtocolFailure;
    NSArray<KCRV3Request *> *pending = _pending.allValues;
    [_pending removeAllObjects];
    [_stateLock unlock];
    KCRV3ClientReply failure = KCRV3Failure(KCRV3TransportProtocolFailure);
    for (KCRV3Request *candidate in pending)
      [candidate completeWithResult:failure];
    return;
  }
  [_pending removeObjectForKey:@(request.requestID)];
  [request completeWithResult:result];
  [_stateLock unlock];
}

- (void)terminalize:(KCRV3TransportStatus)status {
  if (status == KCRV3TransportOK)
    status = KCRV3TransportTerminal;
  [_stateLock lock];
  if (_closed || (_terminal && !_needsReconnect)) {
    [_stateLock unlock];
    return;
  }
  BOOL transient = status == KCRV3TransportTimeout ||
                   status == KCRV3TransportRemoteFailure ||
                   status == KCRV3TransportInterrupted ||
                   status == KCRV3TransportInvalidated;
  _terminal = !transient;
  _needsReconnect = transient;
  _terminalStatus = status;
  NSArray<KCRV3Request *> *pending = _pending.allValues;
  [_pending removeAllObjects];
  NSXPCConnection *connection = _connection;
  [_stateLock unlock];
  KCRV3ClientReply failure = KCRV3Failure(status);
  for (KCRV3Request *request in pending)
    [request completeWithResult:failure];
  if (transient)
    [connection invalidate];
}
- (void)markTransient:(KCRV3TransportStatus)status epoch:(NSUInteger)epoch {
  [_stateLock lock];
  BOOL current = !_closed && epoch == _connectionEpoch;
  [_stateLock unlock];
  if (current)
    [self terminalize:status];
}

- (KCRV3ClientReply)waitWithExpectedReference:(KCRLeaseReferenceV3 *)expectedReference
                       allowIdleWithoutReference:(BOOL)allowIdleWithoutReference
                                          invoke:(void (^)(id<KCRRouteHelperV3Protocol>, void (^)(KCRReplyV3 *)))invoke {
  if (invoke == nil)
    return KCRV3Failure(KCRV3TransportInvalidArgument);
  if (![self ensureConnection])
    return KCRV3Failure(KCRV3TransportInvalidated);
  [_stateLock lock];
  if (_terminal || _nextRequestID == 0 || _nextRequestID == UINT64_MAX) {
    KCRV3TransportStatus status = _terminal ? _terminalStatus : KCRV3TransportProtocolFailure;
    [_stateLock unlock];
    return KCRV3Failure(status);
  }
  uint64_t requestID = _nextRequestID++;
  KCRV3Request *request = [[KCRV3Request alloc]
      initWithRequestID:requestID
       expectedReference:expectedReference
 allowIdleWithoutReference:allowIdleWithoutReference];
  _pending[@(requestID)] = request;
  [_stateLock unlock];

  __weak KCRV3Client *weakSelf = self;
  id<KCRRouteHelperV3Protocol> proxy = [_connection
      remoteObjectProxyWithErrorHandler:^(__unused NSError *error) {
        [weakSelf terminalize:KCRV3TransportRemoteFailure];
      }];
  invoke(proxy, ^(KCRReplyV3 *reply) {
    [weakSelf finishRequest:request reply:reply];
  });
  if (![request waitForNanoseconds:KCRV3TimeoutNanoseconds])
    [self terminalize:KCRV3TransportTimeout];
  return [request result];
}

- (void)close {
  [_stateLock lock];
  if (_closed) {
    [_stateLock unlock];
    return;
  }
  _closed = YES;
  _terminal = YES;
  _needsReconnect = NO;
  NSArray<KCRV3Request *> *pending = _pending.allValues;
  [_pending removeAllObjects];
  NSXPCConnection *connection = _connection;
  [_stateLock unlock];
  KCRV3ClientReply failure = KCRV3Failure(KCRV3TransportInvalidated);
  for (KCRV3Request *request in pending)
    [request completeWithResult:failure];
  [connection invalidate];
}

- (void)dealloc {
  [self close];
}
@end

static KCRLeaseReferenceV3 *KCRV3Reference(uint8_t routeVersion,
                                            uint8_t brokerVersion,
                                            uint64_t generation,
                                            const char *sidecar,
                                            const char *lease,
                                            const char *operation) {
  if (sidecar == NULL || lease == NULL || operation == NULL)
    return nil;
  NSString *sidecarID = [NSString stringWithUTF8String:sidecar];
  NSString *leaseID = [NSString stringWithUTF8String:lease];
  NSString *operationID = [NSString stringWithUTF8String:operation];
  KCRLeaseReferenceV3 *reference =
      [[KCRLeaseReferenceV3 alloc] initWithProtocolVersion:routeVersion
                                      brokerProtocolVersion:brokerVersion
                                           brokerGeneration:generation
                                          sidecarInstanceID:sidecarID
                                                    leaseID:leaseID
                                                 operationID:operationID];
  return [reference isValid] ? reference : nil;
}

void *kyclash_route_helper_v3_client_create(void) {
  return (__bridge_retained void *)[[KCRV3Client alloc] init];
}

void kyclash_route_helper_v3_client_destroy(void *raw) {
  if (raw != NULL)
    CFBridgingRelease(raw);
}

KCRV3ClientReply kyclash_route_helper_v3_client_discover(void *raw) {
  KCRV3Client *client = (__bridge KCRV3Client *)raw;
  if (client == nil)
    return KCRV3Failure(KCRV3TransportInvalidArgument);
  return [client waitWithExpectedReference:nil
                    allowIdleWithoutReference:NO
                                       invoke:^(id<KCRRouteHelperV3Protocol> proxy,
                                                void (^reply)(KCRReplyV3 *)) {
    [proxy discoverV3WithReply:reply];
  }];
}

KCRV3ClientReply kyclash_route_helper_v3_client_owner(
    void *raw, int32_t method, uint8_t routeVersion, uint8_t brokerVersion,
    uint64_t generation, const char *sidecar, const char *lease,
    const char *operation, const char *interfaceName,
    const char *tunnelOperation, uint16_t mtu, uint64_t revision,
    uint8_t hasIPv4, uint8_t hasIPv6, const char *const *mihomoInterfaces,
    size_t mihomoCount, const char *const *privateCIDRs, size_t cidrCount) {
  if (raw == NULL || (method != 0 && method != 1) || interfaceName == NULL ||
      tunnelOperation == NULL || revision == 0 || revision > KCRV3MaximumGeneration ||
      hasIPv4 > 1 || hasIPv6 > 1 || mihomoCount > KCRV3MaximumMihomoInterfaces ||
      (mihomoCount > 0 && mihomoInterfaces == NULL) || privateCIDRs == NULL ||
      cidrCount == 0 || cidrCount > KCRV3MaximumCIDRs)
    return KCRV3Failure(KCRV3TransportInvalidArgument);
  KCRLeaseReferenceV3 *reference = KCRV3Reference(
      routeVersion, brokerVersion, generation, sidecar, lease, operation);
  NSString *interfaceID = [NSString stringWithUTF8String:interfaceName];
  NSString *tunnelOperationID = [NSString stringWithUTF8String:tunnelOperation];
  if (reference == nil || interfaceID == nil || tunnelOperationID == nil)
    return KCRV3Failure(KCRV3TransportInvalidArgument);
  NSMutableArray<NSString *> *mihomo = [NSMutableArray arrayWithCapacity:mihomoCount];
  for (size_t index = 0; index < mihomoCount; index++) {
    if (mihomoInterfaces[index] == NULL)
      return KCRV3Failure(KCRV3TransportInvalidArgument);
    NSString *value = [NSString stringWithUTF8String:mihomoInterfaces[index]];
    if (value == nil)
      return KCRV3Failure(KCRV3TransportInvalidArgument);
    [mihomo addObject:value];
  }
  NSMutableArray<NSString *> *cidrs = [NSMutableArray arrayWithCapacity:cidrCount];
  for (size_t index = 0; index < cidrCount; index++) {
    if (privateCIDRs[index] == NULL)
      return KCRV3Failure(KCRV3TransportInvalidArgument);
    NSString *value = [NSString stringWithUTF8String:privateCIDRs[index]];
    if (value == nil)
      return KCRV3Failure(KCRV3TransportInvalidArgument);
    [cidrs addObject:value];
  }
  KCRLeaseOwnerV3 *owner = [[KCRLeaseOwnerV3 alloc]
      initWithReference:reference
       sidecarInstanceID:reference.sidecarInstanceID
            interfaceName:interfaceID
        tunnelOperationID:tunnelOperationID
                      mtu:mtu
          profileRevision:revision
                hasIPv4:(BOOL)hasIPv4
                hasIPv6:(BOOL)hasIPv6
    activeMihomoTunInterfaces:mihomo
                 privateCIDRs:cidrs];
  if (owner == nil || ![owner isValid])
    return KCRV3Failure(KCRV3TransportInvalidArgument);
  KCRV3Client *client = (__bridge KCRV3Client *)raw;
  return [client waitWithExpectedReference:reference
                    allowIdleWithoutReference:NO
                                       invoke:^(id<KCRRouteHelperV3Protocol> proxy,
                                                void (^reply)(KCRReplyV3 *)) {
    if (method == 0)
      [proxy beginV3:owner reply:reply];
    else
      [proxy recoverV3:owner reply:reply];
  }];
}

KCRV3ClientReply kyclash_route_helper_v3_client_reference(
    void *raw, int32_t method, uint8_t routeVersion, uint8_t brokerVersion,
    uint64_t generation, const char *sidecar, const char *lease,
    const char *operation) {
  if (raw == NULL || method < 0 || method > 3)
    return KCRV3Failure(KCRV3TransportInvalidArgument);
  KCRLeaseReferenceV3 *reference = KCRV3Reference(
      routeVersion, brokerVersion, generation, sidecar, lease, operation);
  if (reference == nil)
    return KCRV3Failure(KCRV3TransportInvalidArgument);
  KCRV3Client *client = (__bridge KCRV3Client *)raw;
  return [client waitWithExpectedReference:reference
                    allowIdleWithoutReference:(method == 1)
                                       invoke:^(id<KCRRouteHelperV3Protocol> proxy,
                                                void (^reply)(KCRReplyV3 *)) {
    switch (method) {
    case 0:
      [proxy applyV3:reference reply:reply];
      break;
    case 1:
      [proxy rollbackV3:reference reply:reply];
      break;
    case 2:
      [proxy heartbeatV3:reference reply:reply];
      break;
    case 3:
      [proxy statusV3:reference reply:reply];
      break;
    }
  }];
}
