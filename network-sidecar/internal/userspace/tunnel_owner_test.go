package userspace

import "testing"

func TestUTUNOwnershipIdentifiersFailClosed(t *testing.T) {
	for _, name := range []string{"utun0", "utun12", "utun999"} {
		if !validUTUNName(name) {
			t.Fatalf("valid created utun name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "utun", "utun-1", "utun1x", "en0", "UTUN1", "utun1/../../"} {
		if validUTUNName(name) {
			t.Fatalf("forged utun name accepted: %q", name)
		}
	}
}
