package externalpeerhost

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const remoteFrameDomain = "net.kysion.kyclash.external-peer.host-runner-result/v1"

// remotePythonProgram is executed only through the fixed management SSH
// boundary. It verifies the guest identity before the read/create action in
// the same SSH session and emits a bounded identity-bound result frame.
const remotePythonProgram = `
import os, platform, pwd, re, stat, subprocess, sys, time
def die(code):
    raise SystemExit(code)
def run(argv):
    try:
        return subprocess.check_output(argv, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        die(71)
def witness(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_nlink,
        stat.S_IMODE(value.st_mode), value.st_size, value.st_mtime_ns)
def directory_witness(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
        stat.S_IMODE(value.st_mode))
if len(sys.argv) != 15:
    die(71)
action, path = sys.argv[1], sys.argv[2]
expected_uuid, expected_mac, expected_ip = sys.argv[3], sys.argv[4], sys.argv[5]
expected_fp, expected_uid, expected_user = sys.argv[6], int(sys.argv[7]), sys.argv[8]
host_wall, expected_owner = int(sys.argv[9]), int(sys.argv[10])
expected_mode, maximum = int(sys.argv[11], 8), int(sys.argv[12])
expected_parent_owner = int(sys.argv[13])
expected_parent_mode = int(sys.argv[14], 8)
model = run(['/usr/sbin/sysctl', '-n', 'hw.model'])
architecture = platform.machine()
ioreg = run(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'])
uuid_match = re.findall(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"', ioreg)
ifconfig = run(['/sbin/ifconfig', 'en0'])
mac_match = re.findall(r'(?m)^\s*ether\s+([0-9A-Fa-f:]{17})\s*$', ifconfig)
ip_match = re.findall(r'(?m)^\s*inet\s+([0-9.]+)\s+', ifconfig)
host_key = run(['/usr/bin/ssh-keygen', '-lf', '/etc/ssh/ssh_host_ed25519_key.pub', '-E', 'sha256']).split()
if len(uuid_match) != 1 or len(mac_match) != 1 or len(ip_match) != 1 or len(host_key) < 2:
    die(71)
platform_uuid = uuid_match[0].lower()
en0_mac = mac_match[0].lower()
en0_ip = ip_match[0]
ssh_fp = host_key[1]
console_uid = os.getuid()
console_user = pwd.getpwuid(console_uid).pw_name
guest_wall = int(time.time())
if (not model.startswith('VirtualMac') or architecture != 'arm64' or
    platform_uuid != expected_uuid.lower() or en0_mac != expected_mac.lower() or
    en0_ip != expected_ip or ssh_fp != expected_fp or
    console_uid != expected_uid or console_user != expected_user or
    abs(guest_wall - host_wall) > 30 or maximum < 0 or maximum > 262144 or
    expected_parent_owner < 0 or expected_parent_mode < 0):
    die(71)
flags = os.O_NOFOLLOW | os.O_CLOEXEC
parent_path, name = os.path.dirname(path), os.path.basename(path)
if (not path.startswith('/') or not parent_path.startswith('/') or
    name in ('', '.', '..') or '/' in name):
    die(71)
try:
    parent_fd = os.open(parent_path,
        os.O_RDONLY | os.O_DIRECTORY | flags)
except Exception:
    die(72)
parent_before = os.fstat(parent_fd)
try:
    parent_path_before = os.lstat(parent_path)
except Exception:
    os.close(parent_fd)
    die(72)
if (directory_witness(parent_before) != directory_witness(parent_path_before) or
    not stat.S_ISDIR(parent_before.st_mode) or
    parent_before.st_uid != expected_parent_owner or
    stat.S_IMODE(parent_before.st_mode) != expected_parent_mode):
    os.close(parent_fd)
    die(72)
payload = b''
if action == 'read':
    try:
        fd = os.open(name, os.O_RDONLY | flags, dir_fd=parent_fd)
    except FileNotFoundError:
        os.close(parent_fd)
        die(44)
    except Exception:
        os.close(parent_fd)
        die(72)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_owner or
            before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != expected_mode or
            before.st_size < 0 or before.st_size > maximum):
            die(72)
        payload = os.read(fd, maximum + 1)
        if len(payload) != before.st_size or len(payload) > maximum:
            die(72)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if witness(before) != witness(after) or witness(after) != witness(current):
            die(72)
    finally:
        os.close(fd)
elif action == 'create':
    payload_in = sys.stdin.buffer.read(maximum + 1)
    if len(payload_in) > maximum:
        os.close(parent_fd)
        die(73)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags,
            expected_mode, dir_fd=parent_fd)
    except FileExistsError:
        os.close(parent_fd)
        die(45)
    except Exception:
        os.close(parent_fd)
        die(73)
    created = True
    try:
        os.fchmod(fd, expected_mode)
        offset = 0
        while offset < len(payload_in):
            written = os.write(fd, payload_in[offset:])
            if written <= 0:
                die(73)
            offset += written
        os.fsync(fd)
        created = os.fstat(fd)
        if (not stat.S_ISREG(created.st_mode) or created.st_uid != expected_owner or
            created.st_nlink != 1 or stat.S_IMODE(created.st_mode) != expected_mode or
            created.st_size != len(payload_in)):
            die(73)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if witness(created) != witness(current):
            die(73)
    except BaseException:
        try:
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception:
            pass
        raise
    finally:
        os.close(fd)
else:
    os.close(parent_fd)
    die(71)
parent_after = os.fstat(parent_fd)
try:
    parent_path_after = os.lstat(parent_path)
except Exception:
    if action == 'create':
        try:
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception:
            pass
    os.close(parent_fd)
    die(72)
if (directory_witness(parent_before) != directory_witness(parent_after) or
    directory_witness(parent_after) != directory_witness(parent_path_after) or
    parent_after.st_uid != expected_parent_owner or
    stat.S_IMODE(parent_after.st_mode) != expected_parent_mode):
    if action == 'create':
        try:
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception:
            pass
    os.close(parent_fd)
    die(72)
if action == 'create':
    os.fsync(parent_fd)
os.close(parent_fd)
lines = [
    'net.kysion.kyclash.external-peer.host-runner-result/v1',
    'model=' + model,
    'architecture=' + architecture,
    'platform_uuid=' + platform_uuid,
    'en0_mac=' + en0_mac,
    'en0_ipv4=' + en0_ip,
    'ssh_host_fingerprint=' + ssh_fp,
    'console_user=' + console_user,
    'console_uid=' + str(console_uid),
    'unix_time=' + str(guest_wall),
    'payload_length=' + str(len(payload)),
    '',
]
sys.stdout.buffer.write(('\n'.join(lines) + '\n').encode('utf-8') + payload)
`

type remoteIdentity struct {
	Model              string
	Architecture       string
	PlatformUUID       string
	MAC                string
	IPv4               string
	SSHHostFingerprint string
	ConsoleUser        string
	ConsoleUID         uint32
	UnixTime           int64
}

func decodeRemoteFrame(
	data []byte,
	role roleContract,
	expectedHostWall time.Time,
	maximumPayload int,
) ([]byte, error) {
	if maximumPayload < 0 || maximumPayload > maximumHostArtifactBytes ||
		len(data) > maximumPayload+4096 {
		return nil, ErrUnsafeHostCourier
	}
	separator := bytes.Index(data, []byte("\n\n"))
	if separator < 0 || separator > 4096 {
		return nil, ErrUnsafeHostCourier
	}
	header := string(data[:separator])
	lines := strings.Split(header, "\n")
	if len(lines) != 11 || lines[0] != remoteFrameDomain {
		return nil, ErrUnsafeHostCourier
	}
	expectedKeys := []string{
		"model",
		"architecture",
		"platform_uuid",
		"en0_mac",
		"en0_ipv4",
		"ssh_host_fingerprint",
		"console_user",
		"console_uid",
		"unix_time",
		"payload_length",
	}
	values := make(map[string]string, len(expectedKeys))
	for index, key := range expectedKeys {
		prefix := key + "="
		if !strings.HasPrefix(lines[index+1], prefix) {
			return nil, ErrUnsafeHostCourier
		}
		value := strings.TrimPrefix(lines[index+1], prefix)
		if value == "" || strings.ContainsAny(value, "\r\x00") {
			return nil, ErrUnsafeHostCourier
		}
		values[key] = value
	}
	uid, err := strconv.ParseUint(values["console_uid"], 10, 32)
	if err != nil {
		return nil, ErrUnsafeHostCourier
	}
	guestUnix, err := strconv.ParseInt(values["unix_time"], 10, 64)
	if err != nil {
		return nil, ErrUnsafeHostCourier
	}
	payloadLength, err := strconv.ParseInt(values["payload_length"], 10, 32)
	if err != nil || payloadLength < 0 || payloadLength > int64(maximumPayload) {
		return nil, ErrUnsafeHostCourier
	}
	payload := data[separator+2:]
	if int64(len(payload)) != payloadLength {
		return nil, ErrUnsafeHostCourier
	}
	if !strings.HasPrefix(values["model"], "VirtualMac") ||
		len(values["model"]) > 128 ||
		values["architecture"] != "arm64" ||
		!equalFoldUUID(values["platform_uuid"], role.facts.PlatformUUID) ||
		!equalMACString(values["en0_mac"], role.facts.MAC) ||
		values["en0_ipv4"] != netip.AddrFrom4(role.facts.IPv4).String() ||
		values["ssh_host_fingerprint"] != role.facts.SSHHostFingerprint ||
		values["console_user"] != managementConsoleUser ||
		uint32(uid) != role.consoleUID ||
		absoluteSeconds(guestUnix-expectedHostWall.Unix()) > 30 {
		return nil, ErrUnsafeHostCourier
	}
	return append([]byte(nil), payload...), nil
}

func encodeRemoteFrameForTest(
	identity remoteIdentity,
	payload []byte,
) []byte {
	header := fmt.Sprintf(
		"%s\nmodel=%s\narchitecture=%s\nplatform_uuid=%s\n"+
			"en0_mac=%s\nen0_ipv4=%s\nssh_host_fingerprint=%s\n"+
			"console_user=%s\nconsole_uid=%d\nunix_time=%d\npayload_length=%d\n\n",
		remoteFrameDomain,
		identity.Model,
		identity.Architecture,
		identity.PlatformUUID,
		identity.MAC,
		identity.IPv4,
		identity.SSHHostFingerprint,
		identity.ConsoleUser,
		identity.ConsoleUID,
		identity.UnixTime,
		len(payload),
	)
	return append([]byte(header), payload...)
}

func equalFoldUUID(left, right string) bool {
	return len(left) == 36 && len(right) == 36 &&
		strings.EqualFold(left, right)
}

func equalMACString(value string, expected [6]byte) bool {
	parsed, err := net.ParseMAC(value)
	return err == nil && len(parsed) == len(expected) &&
		bytes.Equal(parsed, expected[:])
}

func absoluteSeconds(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
