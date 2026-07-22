#import <Foundation/Foundation.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  int32_t transport_status;
  int32_t protocol_version;
  int32_t state;
  int32_t error_code;
} KCRClientReply;

static const uint8_t KCRProtocolVersion = 2;

void *kyclash_route_helper_client_create(void);
void kyclash_route_helper_client_destroy(void *raw);
KCRClientReply kyclash_route_helper_client_discover(void *raw);
KCRClientReply kyclash_route_helper_client_owner(
    void *raw, int32_t method, uint8_t version, const char *lease,
    const char *operation, const char *instance, const char *interface_name,
    const char *tunnel_operation, uint16_t mtu, uint64_t revision,
    uint8_t has_ipv4, uint8_t has_ipv6, const char *const *mihomo_interfaces,
    uintptr_t mihomo_count, const char *const *cidrs, uintptr_t cidr_count);
KCRClientReply kyclash_route_helper_client_reference(void *raw, int32_t method,
                                                     uint8_t version,
                                                     const char *lease,
                                                     const char *operation);

static BOOL requireReply(NSString *step, KCRClientReply reply, int32_t state) {
  printf("%s transport_status=%d protocol_version=%d state=%d error_code=%d\n",
         step.UTF8String, reply.transport_status, reply.protocol_version,
         reply.state, reply.error_code);
  return reply.transport_status == 0 &&
         reply.protocol_version == KCRProtocolVersion && reply.state == state &&
         reply.error_code == 0;
}

static BOOL requireError(NSString *step, KCRClientReply reply, int32_t state,
                         int32_t errorCode) {
  printf("%s transport_status=%d protocol_version=%d state=%d error_code=%d\n",
         step.UTF8String, reply.transport_status, reply.protocol_version,
         reply.state, reply.error_code);
  return reply.transport_status == 0 &&
         reply.protocol_version == KCRProtocolVersion && reply.state == state &&
         reply.error_code == errorCode;
}

static BOOL isCanonicalUtunInterface(const char *value) {
  if (value == NULL)
    return NO;
  size_t length = strlen(value);
  if (length < 5 || length > 15 || strncmp(value, "utun", 4) != 0)
    return NO;
  for (size_t index = 4; index < length; index++) {
    if (value[index] < '0' || value[index] > '9')
      return NO;
  }
  return length == 5 || value[4] != '0';
}

static void printUsage(const char *executable) {
  fprintf(stderr,
          "usage: %s [utun-interface] [--mihomo-utun utunN] | "
          "%s --dual-stack [utun-interface] [--mihomo-utun utunN] | "
          "%s --expect-conflict --dual-stack [utun-interface] "
          "[--mihomo-utun utunN] | "
          "%s --hold-after-apply --dual-stack [utun-interface] "
          "[--mihomo-utun utunN] | "
          "%s --if-nametoindex utunN\n",
          executable, executable, executable, executable, executable);
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc == 3 && strcmp(argv[1], "--if-nametoindex") == 0) {
      if (!isCanonicalUtunInterface(argv[2])) {
        printUsage(argv[0]);
        return 2;
      }
      unsigned int interfaceIndex = if_nametoindex(argv[2]);
      if (interfaceIndex == 0) {
        fprintf(stderr, "if_nametoindex device=%s index=0 exists=false\n",
                argv[2]);
        return 1;
      }
      printf("if_nametoindex device=%s index=%u exists=true\n", argv[2],
             interfaceIndex);
      return 0;
    }

    const char *arguments[5] = {argv[0], NULL, NULL, NULL, NULL};
    int argumentCount = 1;
    const char *mihomoInterface = NULL;
    BOOL argumentsValid = YES;
    for (int index = 1; index < argc; index++) {
      if (strcmp(argv[index], "--mihomo-utun") == 0) {
        if (mihomoInterface != NULL || index + 1 >= argc ||
            !isCanonicalUtunInterface(argv[index + 1])) {
          argumentsValid = NO;
          break;
        }
        mihomoInterface = argv[++index];
      } else if (argumentCount >= 5) {
        argumentsValid = NO;
        break;
      } else {
        arguments[argumentCount++] = argv[index];
      }
    }
    if (mihomoInterface != NULL && argumentCount == 1)
      argumentsValid = NO;
    BOOL dualStack = argumentCount == 3 &&
                     strcmp(arguments[1], "--dual-stack") == 0;
    BOOL expectConflict = argumentCount == 4 &&
                          strcmp(arguments[1], "--expect-conflict") == 0 &&
                          strcmp(arguments[2], "--dual-stack") == 0;
    BOOL holdAfterApply = argumentCount == 4 &&
                          strcmp(arguments[1], "--hold-after-apply") == 0 &&
                          strcmp(arguments[2], "--dual-stack") == 0;
    BOOL routeMode = argumentCount == 2 || dualStack || expectConflict ||
                     holdAfterApply;
    if (!argumentsValid || (argumentCount != 1 && !routeMode)) {
      printUsage(argv[0]);
      return 2;
    }

    void *client = kyclash_route_helper_client_create();
    BOOL passed = requireReply(@"discover",
                               kyclash_route_helper_client_discover(client), 0);
    if (passed && routeMode) {
      // The Virtualization.framework guest owns the TEST-NET blocks on its
      // en0 underlay. Use a fixed private pair that is absent from that
      // underlay so the fixture never edits an unrelated route.
      const char *cidrs[] = {"10.200.0.0/16", "fd00:200::/48"};
      const char *mihomoInterfaces[] = {mihomoInterface};
      uintptr_t mihomoCount = mihomoInterface == NULL ? 0 : 1;
      const char *const *mihomoValues =
          mihomoCount == 0 ? NULL : mihomoInterfaces;
      uintptr_t cidrCount =
          (dualStack || expectConflict || holdAfterApply) ? 2 : 1;
      const char *interfaceName = dualStack        ? arguments[2]
                                  : expectConflict ? arguments[3]
                                  : holdAfterApply ? arguments[3]
                                                   : arguments[1];
      KCRClientReply begin = kyclash_route_helper_client_owner(
          client, 0, KCRProtocolVersion, "lease.lab.route.v2",
          "operation.lab.route.v2", "sidecar.lab.route.v2", interfaceName,
          "operation.lab.route.v2.prepare", 1420, 1, 1, 1, mihomoValues,
          mihomoCount, cidrs, cidrCount);
      passed = expectConflict ? requireError(@"begin", begin, 4, 9)
                              : requireReply(@"begin", begin, 1);
      if (expectConflict) {
        kyclash_route_helper_client_destroy(client);
        return passed ? 0 : 1;
      }
      passed = passed &&
               requireReply(@"apply",
                            kyclash_route_helper_client_reference(
                                client, 0, KCRProtocolVersion,
                                "lease.lab.route.v2", "operation.lab.route.v2"),
                            2);
      passed = passed &&
               requireReply(@"status",
                            kyclash_route_helper_client_reference(
                                client, 3, KCRProtocolVersion,
                                "lease.lab.route.v2", "operation.lab.route.v2"),
                            2);
      if (passed && holdAfterApply) {
        printf("KYCLASH_ROUTE_HELPER_LAB_READY state=applied\n");
        fflush(stdout);
        for (;;) {
          pause();
        }
      }
      passed = passed &&
               requireReply(@"rollback",
                            kyclash_route_helper_client_reference(
                                client, 1, KCRProtocolVersion,
                                "lease.lab.route.v2", "operation.lab.route.v2"),
                            0);
    }
    kyclash_route_helper_client_destroy(client);
    return passed ? 0 : 1;
  }
}
