#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  int32_t transport_status;
  int32_t state;
  int32_t error_code;
} KCRClientReply;

void *kyclash_route_helper_client_create(void);
void kyclash_route_helper_client_destroy(void *raw);
KCRClientReply kyclash_route_helper_client_discover(void *raw);
KCRClientReply kyclash_route_helper_client_owner(
    void *raw, int32_t method, uint8_t version, const char *lease,
    const char *operation, const char *instance, const char *interface_name,
    const char *tunnel_operation, uint16_t mtu, uint64_t revision,
    const char *const *cidrs, uintptr_t cidr_count);
KCRClientReply kyclash_route_helper_client_reference(void *raw, int32_t method,
                                                     uint8_t version,
                                                     const char *lease,
                                                     const char *operation);

static BOOL requireReply(NSString *step, KCRClientReply reply, int32_t state) {
  printf("%s transport_status=%d state=%d error_code=%d\n", step.UTF8String,
         reply.transport_status, reply.state, reply.error_code);
  return reply.transport_status == 0 && reply.state == state &&
         reply.error_code == 0;
}

static BOOL requireError(NSString *step, KCRClientReply reply, int32_t state,
                         int32_t errorCode) {
  printf("%s transport_status=%d state=%d error_code=%d\n", step.UTF8String,
         reply.transport_status, reply.state, reply.error_code);
  return reply.transport_status == 0 && reply.state == state &&
         reply.error_code == errorCode;
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    void *client = kyclash_route_helper_client_create();
    BOOL passed = requireReply(@"discover",
                               kyclash_route_helper_client_discover(client), 0);
    BOOL dualStack = argc == 3 && strcmp(argv[1], "--dual-stack") == 0;
    BOOL expectConflict = argc == 4 &&
                          strcmp(argv[1], "--expect-conflict") == 0 &&
                          strcmp(argv[2], "--dual-stack") == 0;
    BOOL holdAfterApply = argc == 4 &&
                          strcmp(argv[1], "--hold-after-apply") == 0 &&
                          strcmp(argv[2], "--dual-stack") == 0;
    if (passed &&
        (argc == 2 || dualStack || expectConflict || holdAfterApply)) {
      const char *cidrs[] = {"192.0.2.0/24", "fd00:64::/48"};
      uintptr_t cidrCount =
          (dualStack || expectConflict || holdAfterApply) ? 2 : 1;
      const char *interfaceName = dualStack        ? argv[2]
                                  : expectConflict ? argv[3]
                                  : holdAfterApply ? argv[3]
                                                   : argv[1];
      KCRClientReply begin = kyclash_route_helper_client_owner(
          client, 0, 1, "lease.lab.route.v1", "operation.lab.route.v1",
          "sidecar.lab.route.v1", interfaceName,
          "operation.lab.route.v1.prepare", 1420, 1, cidrs, cidrCount);
      passed = expectConflict ? requireError(@"begin", begin, 4, 9)
                              : requireReply(@"begin", begin, 1);
      if (expectConflict) {
        kyclash_route_helper_client_destroy(client);
        return passed ? 0 : 1;
      }
      passed = passed && requireReply(@"apply",
                                      kyclash_route_helper_client_reference(
                                          client, 0, 1, "lease.lab.route.v1",
                                          "operation.lab.route.v1"),
                                      2);
      passed = passed && requireReply(@"status",
                                      kyclash_route_helper_client_reference(
                                          client, 3, 1, "lease.lab.route.v1",
                                          "operation.lab.route.v1"),
                                      2);
      if (passed && holdAfterApply) {
        printf("KYCLASH_ROUTE_HELPER_LAB_READY state=applied\n");
        fflush(stdout);
        for (;;) {
          pause();
        }
      }
      passed = passed && requireReply(@"rollback",
                                      kyclash_route_helper_client_reference(
                                          client, 1, 1, "lease.lab.route.v1",
                                          "operation.lab.route.v1"),
                                      0);
    } else if (argc != 1) {
      fprintf(stderr,
              "usage: %s [utun-interface] | %s --dual-stack "
              "[utun-interface] | %s --expect-conflict --dual-stack "
              "[utun-interface] | %s --hold-after-apply --dual-stack "
              "[utun-interface]\n",
              argv[0], argv[0], argv[0], argv[0]);
      passed = NO;
    }
    kyclash_route_helper_client_destroy(client);
    return passed ? 0 : 1;
  }
}
