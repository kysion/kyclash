#ifndef KYCLASH_TUNNEL_BROKER_ROUTE_CLIENT_H
#define KYCLASH_TUNNEL_BROKER_ROUTE_CLIENT_H

// C ABI for the root-only broker route bridge.  The route helper owns the
// only production caller; the application process must not link this header.
// Keep the result POD so Swift/Rust callers cannot receive an Objective-C
// object or an untyped command surface across the privilege boundary.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

typedef enum KCTBRTransportStatus {
  KCTBRTransportOK = 0,
  KCTBRTransportTimeout = 1,
  KCTBRTransportRemoteFailure = 2,
  KCTBRTransportInterrupted = 3,
  KCTBRTransportInvalidated = 4,
  KCTBRTransportProtocolFailure = 5,
  KCTBRTransportTerminal = 6,
  KCTBRTransportInvalidArgument = 7,
} KCTBRTransportStatus;

void *kyclash_tunnel_broker_route_client_create(void);
void kyclash_tunnel_broker_route_client_destroy(void *client);

KCTBRClientReply kyclash_tunnel_broker_route_client_hold(
    void *client, int32_t route_version, int32_t broker_version,
    uint64_t broker_generation, const char *sidecar_instance_id,
    const char *route_lease_id, const char *operation_id);
KCTBRClientReply kyclash_tunnel_broker_route_client_release(
    void *client, int32_t route_version, int32_t broker_version,
    uint64_t broker_generation, const char *sidecar_instance_id,
    const char *route_lease_id, const char *operation_id);
KCTBRClientReply kyclash_tunnel_broker_route_client_status(
    void *client, int32_t route_version, int32_t broker_version,
    uint64_t broker_generation, const char *sidecar_instance_id,
    const char *route_lease_id, const char *operation_id);

#ifdef __cplusplus
}
#endif

#endif
