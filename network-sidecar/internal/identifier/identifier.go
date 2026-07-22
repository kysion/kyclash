// Package identifier defines the shared sidecar identifier wire contract.
package identifier

// Valid reports whether value is a bounded ASCII identifier. Dots are segment
// separators: they cannot lead, trail, or repeat. This keeps production IDs
// such as kyclash.<hex> valid without admitting path-shaped values.
func Valid(value string) bool {
	if len(value) < 8 || len(value) > 64 || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	previousDot := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
		if character == '.' {
			if previousDot {
				return false
			}
			previousDot = true
		} else {
			previousDot = false
		}
	}
	return true
}
