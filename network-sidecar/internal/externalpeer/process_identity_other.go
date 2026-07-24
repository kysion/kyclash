//go:build !darwin

package externalpeer

import (
	"context"
	"strconv"
	"strings"
)

func processStartIdentityAndUID(
	pid int,
) (string, uint32, error) {
	startOutput, err := fixedReadOnlyCommand(
		context.Background(),
		"/bin/ps",
		"-p",
		strconv.Itoa(pid),
		"-o",
		"lstart=",
	)
	if err != nil {
		return "", 0, ErrSupervisorState
	}
	start := strings.TrimSpace(string(startOutput))
	clear(startOutput)
	uidOutput, err := fixedReadOnlyCommand(
		context.Background(),
		"/bin/ps",
		"-p",
		strconv.Itoa(pid),
		"-o",
		"uid=",
	)
	if err != nil {
		return "", 0, ErrSupervisorState
	}
	uid, err := strconv.ParseUint(strings.TrimSpace(string(uidOutput)), 10, 32)
	clear(uidOutput)
	if err != nil || start == "" {
		return "", 0, ErrSupervisorState
	}
	return start, uint32(uid), nil
}
