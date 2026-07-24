//go:build darwin

package externalpeer

import (
	"strconv"

	"golang.org/x/sys/unix"
)

func processStartIdentityAndUID(
	pid int,
) (string, uint32, error) {
	value, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil ||
		value == nil ||
		value.Proc.P_pid != int32(pid) ||
		value.Proc.P_starttime.Sec <= 0 ||
		value.Proc.P_starttime.Usec < 0 ||
		value.Proc.P_starttime.Usec >= 1_000_000 {
		return "", 0, ErrSupervisorState
	}
	start := strconv.FormatInt(value.Proc.P_starttime.Sec, 10) +
		":" +
		strconv.FormatInt(int64(value.Proc.P_starttime.Usec), 10)
	return start, value.Eproc.Ucred.Uid, nil
}
