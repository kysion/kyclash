#ifndef KYCLASH_ROUTE_HELPER_CLIENT_V3_H
#define KYCLASH_ROUTE_HELPER_CLIENT_V3_H

// Typed C ABI for the production route-helper v3 client. This bridge is
// intentionally separate from client.m (the legacy v2 surface) so a v2
// caller can never silently downgrade a broker-bound v3 owner envelope.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int32_t transport_status;
  int32_t protocol_version;
  int32_t state;
  int32_t error_code;
  uint64_t transition;
  uint64_t broker_generation;
  char sidecar_instance_id[65];
  char route_lease_id[65];
  char operation_id[65];
} KCRV3ClientReply;

typedef enum KCRV3TransportStatus {
  KCRV3TransportOK = 0,
  KCRV3TransportTimeout = 1,
  KCRV3TransportRemoteFailure = 2,
  KCRV3TransportInterrupted = 3,
  KCRV3TransportInvalidated = 4,
  KCRV3TransportProtocolFailure = 5,
  KCRV3TransportTerminal = 6,
  KCRV3TransportInvalidArgument = 7,
} KCRV3TransportStatus;

// Stable v3 reply error codes.  The string vocabulary is validated at the
// NSSecureCoding boundary; these numeric values are the C ABI projection.
typedef enum KCRV3ErrorCode {
  KCRV3ErrorNone = 0,
  KCRV3ErrorNotReady = 1,
  KCRV3ErrorInvalidOwner = 2,
  KCRV3ErrorPermissionDenied = 3,
  KCRV3ErrorJournalWriteFailed = 4,
  KCRV3ErrorJournalCorrupt = 5,
  KCRV3ErrorRouteApplyFailed = 6,
  KCRV3ErrorRollbackOrReleaseFailed = 7,
  KCRV3ErrorRouteConflict = 8,
  KCRV3ErrorRecoveryRequired = 9,
  KCRV3ErrorOwnershipMismatch = 10,
  KCRV3ErrorBrokerProtocolFailure = 11,
  KCRV3ErrorBrokerStatusFailed = 12,
} KCRV3ErrorCode;

void *kyclash_route_helper_v3_client_create(void);
void kyclash_route_helper_v3_client_destroy(void *client);

KCRV3ClientReply kyclash_route_helper_v3_client_discover(void *client);

// method 0 = beginV3, method 1 = recoverV3.  The owner carries the complete
// broker/lease/operation tuple and all normalized tunnel/route facts.
KCRV3ClientReply kyclash_route_helper_v3_client_owner(
    void *client, int32_t method, uint8_t route_version,
    uint8_t broker_version, uint64_t broker_generation,
    const char *sidecar_instance_id, const char *route_lease_id,
    const char *operation_id, const char *interface_name,
    const char *tunnel_operation_id, uint16_t mtu, uint64_t profile_revision,
    uint8_t has_ipv4, uint8_t has_ipv6, const char *const *mihomo_interfaces,
    size_t mihomo_count, const char *const *private_cidrs, size_t cidr_count);

// method 0 = applyV3, 1 = rollbackV3, 2 = heartbeatV3, 3 = statusV3.
KCRV3ClientReply kyclash_route_helper_v3_client_reference(
    void *client, int32_t method, uint8_t route_version,
    uint8_t broker_version, uint64_t broker_generation,
    const char *sidecar_instance_id, const char *route_lease_id,
    const char *operation_id);

#ifdef __cplusplus
}
#endif

#endif
