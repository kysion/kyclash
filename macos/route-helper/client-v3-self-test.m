#import "client-v3.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
  KCRV3ClientReply discover = kyclash_route_helper_v3_client_discover(NULL);
  assert(discover.transport_status == KCRV3TransportInvalidArgument);
  assert(discover.protocol_version < 0);

  KCRV3ClientReply reference = kyclash_route_helper_v3_client_reference(
      NULL, 0, 3, 1, 17, "instance.v3.test", "lease.v3.test",
      "operation.v3.test");
  assert(reference.transport_status == KCRV3TransportInvalidArgument);

  KCRV3ClientReply owner = kyclash_route_helper_v3_client_owner(
      NULL, 0, 3, 1, 17, "instance.v3.test", "lease.v3.test",
      "operation.v3.test", "utun42", "operation.v3.test.prepare", 1420,
      7, 1, 1, NULL, 0, NULL, 0);
  assert(owner.transport_status == KCRV3TransportInvalidArgument);

  // Exercise the non-IPC owner envelope validators.  Each case must fail
  // before the client can enqueue an XPC request, so this test never depends
  // on a running privileged helper.
  void *client = kyclash_route_helper_v3_client_create();
  assert(client != NULL);
  const char *malformedCIDR[] = {"10.64.1.0/16"};
  KCRV3ClientReply malformed = kyclash_route_helper_v3_client_owner(
      client, 0, 3, 1, 17, "instance.v3.test", "lease.v3.test",
      "operation.v3.test", "utun42", "operation.v3.test.prepare", 1420,
      7, 1, 1, NULL, 0, malformedCIDR, 1);
  assert(malformed.transport_status == KCRV3TransportInvalidArgument);

  const char *overlappingCIDRs[] = {"10.64.0.0/16", "10.64.1.0/24"};
  KCRV3ClientReply overlapping = kyclash_route_helper_v3_client_owner(
      client, 0, 3, 1, 17, "instance.v3.test", "lease.v3.test",
      "operation.v3.test", "utun42", "operation.v3.test.prepare", 1420,
      7, 1, 1, NULL, 0, overlappingCIDRs, 2);
  assert(overlapping.transport_status == KCRV3TransportInvalidArgument);

  const char *multicastCIDR[] = {"224.0.0.0/4"};
  KCRV3ClientReply multicast = kyclash_route_helper_v3_client_owner(
      client, 0, 3, 1, 17, "instance.v3.test", "lease.v3.test",
      "operation.v3.test", "utun42", "operation.v3.test.prepare", 1420,
      7, 1, 1, NULL, 0, multicastCIDR, 1);
  assert(multicast.transport_status == KCRV3TransportInvalidArgument);

  const char *familyCIDR[] = {"10.64.0.0/16"};
  KCRV3ClientReply family = kyclash_route_helper_v3_client_owner(
      client, 0, 3, 1, 17, "instance.v3.test", "lease.v3.test",
      "operation.v3.test", "utun42", "operation.v3.test.prepare", 1420,
      7, 0, 1, NULL, 0, familyCIDR, 1);
  assert(family.transport_status == KCRV3TransportInvalidArgument);
  kyclash_route_helper_v3_client_destroy(client);

  puts("route_helper_v3_client_self_test_ok");
  return 0;
}
