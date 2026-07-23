//go:build !linux && !darwin

package productionpeer

func ReadLinuxConfig() ([]byte, error) {
	return nil, ErrInvalidConfig
}
