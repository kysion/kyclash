package userspace

import "strings"

func validUTUNName(name string) bool {
	suffix := strings.TrimPrefix(name, "utun")
	if suffix == name || suffix == "" {
		return false
	}
	for _, character := range suffix {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
