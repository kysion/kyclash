package externalpeergueststaging

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

func readVirtualMacModel() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "hw.model")
	command.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LC_ALL=C",
	}
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 256 ||
		bytes.ContainsAny(output, "\x00\r") {
		clear(output)
		return "", ErrGuestStaging
	}
	model := strings.TrimSpace(string(output))
	clear(output)
	if !strings.HasPrefix(model, "VirtualMac") {
		return "", ErrGuestStaging
	}
	return model, nil
}
