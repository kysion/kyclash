package identifier

import "testing"

func TestValidMatchesProductionIdentifierContract(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"kyclash.0123456789abcdef0123456789abcdef",
		"kyclash.profile.apply.1",
		"instance_test-123",
	} {
		if !Valid(value) {
			t.Errorf("rejected valid identifier %q", value)
		}
	}
	for _, value := range []string{
		"short",
		".kyclash.instance",
		"kyclash.instance.",
		"kyclash..instance",
		"kyclash/instance",
		`kyclash\instance`,
		"kyclash:instance",
		"kyclash.实例",
		"kyclash.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.123456789",
	} {
		if Valid(value) {
			t.Errorf("accepted invalid identifier %q", value)
		}
	}
}
