package externalpeerhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
	"github.com/kysion/kyclash/network-sidecar/internal/vmexternalpeerlab"
)

type publicFileSpec struct {
	name       string
	source     string
	sourceMode os.FileMode
	outputMode os.FileMode
	size       uint64
	sha256     string
}

type phaseInputSpec struct {
	name  string
	files []publicFileSpec
	app   bool
}

func InitializeLayerAInputs(layout Layout) error {
	builds, err := loadExternalPeerBuildInputs(layout)
	if err != nil {
		return err
	}
	courierPublic, managementPublic, err := loadPublicInputKeys(layout)
	if err != nil {
		return err
	}
	defer clear(courierPublic)
	defer clearByteSlices(managementPublic)
	_ = courierPublic // Layer A carries only role-separated management keys.

	specs, err := layerAInputSpecs(layout, builds, managementPublic)
	if err != nil {
		return err
	}
	return publishInputCollection(
		layout,
		LayerAInputsName,
		func(root string) error {
			return populateLayerAInputCollection(root, specs, builds)
		},
		func(root string) error {
			return validateLayerAInputCollection(root, specs, builds)
		},
	)
}

func layerAInputSpecs(
	layout Layout,
	builds externalPeerBuildInputs,
	managementPublic [][]byte,
) ([]phaseInputSpec, error) {
	if len(managementPublic) != 2 {
		return nil, ErrUnsafeHostCourier
	}
	mihomoPath := filepath.Join(
		layout.RepositoryRoot,
		"src-tauri",
		"sidecar",
		"verge-mihomo-aarch64-apple-darwin",
	)
	mihomoDigest, mihomoSize, err := hashStableFile(
		mihomoPath, uint32(os.Getuid()), 0o755, 512*1024*1024,
	)
	if err != nil || mihomoDigest != builds.mihomoSHA256 {
		return nil, ErrUnsafeHostCourier
	}
	mihomoConfigPath := filepath.Join(
		layout.RepositoryRoot,
		"macos",
		"route-helper",
		"vm-external-peer-lab-mihomo-config.json",
	)
	configDigest, configSize, err := hashStableFile(
		mihomoConfigPath, uint32(os.Getuid()), 0o644, 1024*1024,
	)
	if err != nil || configDigest != vmexternalpeerlab.MihomoConfigSHA256 {
		return nil, ErrUnsafeHostCourier
	}
	artifact := func(name string, outputMode os.FileMode) publicFileSpec {
		record, exists := builds.artifacts[name]
		if !exists {
			return publicFileSpec{}
		}
		return publicFileSpec{
			name: name, source: builds.artifactPaths[name],
			sourceMode: 0o755, outputMode: outputMode,
			size: record.ByteLength, sha256: record.SHA256,
		}
	}
	specs := []phaseInputSpec{
		{
			name: filepath.Base(
				externalpeergueststaging.ClientLayerAInput,
			),
			app: true,
			files: []publicFileSpec{
				artifact(
					"kyclash-vm-external-peer-lab-client-stage-layer-a",
					0o500,
				),
				artifact(
					"kyclash-vm-external-peer-lab-supervisor",
					0o500,
				),
				artifact(
					"kyclash-vm-external-peer-lab-harness",
					0o500,
				),
				{
					name:   externalpeergueststaging.MihomoInputName,
					source: mihomoPath, sourceMode: 0o755, outputMode: 0o500,
					size: mihomoSize, sha256: mihomoDigest,
				},
				{
					name:       externalpeergueststaging.MihomoConfigInputName,
					source:     mihomoConfigPath,
					sourceMode: 0o644, outputMode: 0o600,
					size: configSize, sha256: configDigest,
				},
				{
					name:       AppTreeManifestInputName,
					source:     builds.appManifestPath,
					sourceMode: 0o600, outputMode: 0o600,
					size:   builds.appManifestSize,
					sha256: builds.appManifestSHA256,
				},
			},
		},
		{
			name: filepath.Base(
				externalpeergueststaging.ClientSSHBootstrapInput,
			),
			files: []publicFileSpec{
				artifact(
					"kyclash-vm-external-peer-lab-client-bootstrap-ssh-layer-a",
					0o500,
				),
				{
					name: externalpeergueststaging.ClientManagementPublicKeyName,
					source: filepath.Join(
						layout.ManagementPublic,
						ClientManagementPublicName,
					),
					sourceMode: 0o600, outputMode: 0o600,
					size:   uint64(len(managementPublic[0])),
					sha256: hashBytes(managementPublic[0]),
				},
			},
		},
		{
			name: filepath.Base(
				externalpeergueststaging.PeerLayerAInput,
			),
			files: []publicFileSpec{
				artifact(
					"kyclash-vm-external-peer-lab-peer-stage-layer-a",
					0o500,
				),
				artifact(
					"kyclash-vm-external-peer-lab-peer-root-supervisor",
					0o500,
				),
				artifact(
					"kyclash-vm-external-peer-lab-peer",
					0o500,
				),
				artifact(
					"kyclash-vm-external-peer-lab-listener-auditor",
					0o500,
				),
				artifact(
					"kyclash-vm-external-peer-lab-forced-command",
					0o500,
				),
			},
		},
		{
			name: filepath.Base(
				externalpeergueststaging.PeerSSHBootstrapInput,
			),
			files: []publicFileSpec{
				artifact(
					"kyclash-vm-external-peer-lab-peer-bootstrap-ssh-layer-a",
					0o500,
				),
				{
					name: externalpeergueststaging.PeerManagementPublicKeyName,
					source: filepath.Join(
						layout.ManagementPublic,
						PeerManagementPublicName,
					),
					sourceMode: 0o600, outputMode: 0o600,
					size:   uint64(len(managementPublic[1])),
					sha256: hashBytes(managementPublic[1]),
				},
			},
		},
	}
	for _, phase := range specs {
		for _, file := range phase.files {
			if file.name == "" || file.source == "" ||
				file.size == 0 || !validLowerSHA256(file.sha256) {
				return nil, ErrUnsafeHostCourier
			}
		}
	}
	return specs, nil
}

func requirePublishedLayerAInputs(
	layout Layout,
	builds externalPeerBuildInputs,
	managementPublic [][]byte,
) error {
	specs, err := layerAInputSpecs(layout, builds, managementPublic)
	if err != nil {
		return err
	}
	return validateLayerAInputCollection(
		filepath.Join(layout.GuestShare, LayerAInputsName),
		specs,
		builds,
	)
}

func loadPublicInputKeys(
	layout Layout,
) ([]byte, [][]byte, error) {
	uid := uint32(os.Getuid())
	privateRoot, err := openSecureDirectory(layout.PrivateRoot, uid)
	if err != nil {
		return nil, nil, err
	}
	defer privateRoot.close()
	courier, err := privateRoot.readStableFile(
		PublicKeyName, ed25519.PublicKeySize, nil,
	)
	if err != nil || len(courier.bytes) != ed25519.PublicKeySize {
		clear(courier.bytes)
		return nil, nil, ErrUnsafeHostCourier
	}
	publicRoot, err := openSecureDirectory(layout.ManagementPublic, uid)
	if err != nil {
		clear(courier.bytes)
		return nil, nil, err
	}
	defer publicRoot.close()
	if publicRoot.requireExactNames(managementPublicNames) != nil {
		clear(courier.bytes)
		return nil, nil, ErrUnsafeHostCourier
	}
	result := make([][]byte, 0, 2)
	for _, name := range managementPublicNames {
		blob, err := publicRoot.readStableFile(name, 4096, nil)
		if err != nil {
			clear(courier.bytes)
			clearByteSlices(result)
			return nil, nil, err
		}
		key, err := parseCanonicalRawED25519(blob.bytes)
		if err != nil || key.Type() != "ssh-ed25519" {
			clear(blob.bytes)
			clear(courier.bytes)
			clearByteSlices(result)
			return nil, nil, ErrUnsafeHostCourier
		}
		result = append(result, blob.bytes)
	}
	if bytes.Equal(result[0], result[1]) {
		clear(courier.bytes)
		clearByteSlices(result)
		return nil, nil, ErrUnsafeHostCourier
	}
	return courier.bytes, result, nil
}

func populateLayerAInputCollection(
	root string,
	specs []phaseInputSpec,
	builds externalPeerBuildInputs,
) error {
	for _, phase := range specs {
		phaseRoot := filepath.Join(root, phase.name)
		if err := os.Mkdir(phaseRoot, 0o700); err != nil ||
			os.Chmod(phaseRoot, 0o700) != nil {
			return ErrUnsafeHostCourier
		}
		for _, file := range phase.files {
			if err := copyStablePublicFile(
				file.source,
				filepath.Join(phaseRoot, file.name),
				file.sourceMode,
				file.outputMode,
				file.size,
				file.sha256,
			); err != nil {
				return err
			}
		}
		if phase.app {
			if err := copyManifestBoundApp(
				builds.appPath,
				filepath.Join(
					phaseRoot,
					externalpeergueststaging.AppInputName,
				),
				builds.appManifest,
			); err != nil {
				return err
			}
		}
		if err := syncDirectoryPath(phaseRoot); err != nil {
			return err
		}
	}
	return nil
}

func validateLayerAInputCollection(
	root string,
	specs []phaseInputSpec,
	builds externalPeerBuildInputs,
) error {
	expectedPhases := make([]string, 0, len(specs))
	for _, phase := range specs {
		expectedPhases = append(expectedPhases, phase.name)
	}
	if requireExactPrivateDirectory(root, expectedPhases) != nil {
		return ErrUnsafeHostCourier
	}
	for _, phase := range specs {
		phaseRoot := filepath.Join(root, phase.name)
		names := make([]string, 0, len(phase.files)+1)
		for _, file := range phase.files {
			names = append(names, file.name)
			if digest, size, err := hashStableFile(
				filepath.Join(phaseRoot, file.name),
				uint32(os.Getuid()),
				file.outputMode,
				512*1024*1024,
			); err != nil ||
				digest != file.sha256 ||
				size != file.size {
				return ErrUnsafeHostCourier
			}
		}
		if phase.app {
			names = append(names, externalpeergueststaging.AppInputName)
			if validateCopiedApp(
				filepath.Join(
					phaseRoot,
					externalpeergueststaging.AppInputName,
				),
				builds.appManifest,
			) != nil {
				return ErrUnsafeHostCourier
			}
		}
		if requireExactPrivateDirectory(phaseRoot, names) != nil {
			return ErrUnsafeHostCourier
		}
	}
	return validateNoPrivateKeyMaterial(root)
}

func publishInputCollection(
	layout Layout,
	name string,
	populate func(string) error,
	validate func(string) error,
) error {
	if populate == nil || validate == nil || !fixedBaseName(name) {
		return ErrUnsafeHostCourier
	}
	uid := uint32(os.Getuid())
	if err := ensurePrivateRoot(layout.PrivateRoot, uid); err != nil {
		return err
	}
	share, err := openSecureDirectory(layout.GuestShare, uid)
	if err != nil {
		return err
	}
	defer share.close()
	finalPath := filepath.Join(layout.GuestShare, name)
	if _, err := os.Lstat(finalPath); err == nil {
		return validate(finalPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafeHostCourier
	}
	pending, err := os.MkdirTemp(
		layout.PrivateRoot,
		"."+name+".pending.",
	)
	if err != nil || os.Chmod(pending, 0o700) != nil {
		return ErrUnsafeHostCourier
	}
	pendingPresent := true
	defer func() {
		if pendingPresent {
			_ = os.RemoveAll(pending)
		}
	}()
	if sameFileSystem(pending, layout.GuestShare) != nil ||
		populate(pending) != nil ||
		validate(pending) != nil ||
		syncDirectoryPath(pending) != nil ||
		share.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if err := renameDirectoryNoReplace(pending, finalPath); err != nil {
		return err
	}
	pendingPresent = false
	if share.file.Sync() != nil ||
		share.revalidate() != nil ||
		validate(finalPath) != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}

func copyManifestBoundApp(
	source string,
	destination string,
	manifest appTreeManifest,
) error {
	if err := os.Mkdir(destination, 0o700); err != nil ||
		os.Chmod(destination, 0o700) != nil {
		return ErrUnsafeHostCourier
	}
	for index, entry := range manifest.Entries {
		if index == 0 {
			continue
		}
		target := filepath.Join(destination, filepath.FromSlash(entry.RelativePath))
		sourcePath := filepath.Join(source, filepath.FromSlash(entry.RelativePath))
		if entry.Type == "directory" {
			if err := os.Mkdir(target, 0o755); err != nil ||
				os.Chmod(target, 0o755) != nil {
				return ErrUnsafeHostCourier
			}
			continue
		}
		if entry.SHA256 == nil {
			return ErrUnsafeHostCourier
		}
		sourceMode, err := parseMode(entry.Mode)
		if err != nil {
			return err
		}
		outputMode := os.FileMode(0o644)
		if sourceMode&0o111 != 0 {
			outputMode = 0o755
		}
		if err := copyStablePublicFile(
			sourcePath, target, sourceMode, outputMode,
			entry.ByteLength, *entry.SHA256,
		); err != nil {
			return err
		}
	}
	if validateAppTreeOnDisk(source, manifest) != nil {
		return ErrUnsafeHostCourier
	}
	return syncTree(destination)
}

func validateCopiedApp(
	destination string,
	manifest appTreeManifest,
) error {
	rootInfo, err := os.Lstat(destination)
	if err != nil ||
		!safeDirectoryInfo(rootInfo, uint32(os.Getuid())) {
		return ErrUnsafeHostCourier
	}
	for index, entry := range manifest.Entries {
		if index == 0 {
			continue
		}
		target := filepath.Join(destination, filepath.FromSlash(entry.RelativePath))
		info, err := os.Lstat(target)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeHostCourier
		}
		if entry.Type == "directory" {
			if !safeBuildDirectory(info, uint32(os.Getuid())) ||
				info.Mode().Perm() != 0o755 {
				return ErrUnsafeHostCourier
			}
			continue
		}
		if entry.SHA256 == nil {
			return ErrUnsafeHostCourier
		}
		sourceMode, err := parseMode(entry.Mode)
		if err != nil {
			return err
		}
		outputMode := os.FileMode(0o644)
		if sourceMode&0o111 != 0 {
			outputMode = 0o755
		}
		digest, size, err := hashStableFile(
			target, uint32(os.Getuid()), outputMode, 512*1024*1024,
		)
		if err != nil || digest != *entry.SHA256 ||
			size != entry.ByteLength {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func copyStablePublicFile(
	source string,
	destination string,
	sourceMode os.FileMode,
	outputMode os.FileMode,
	expectedSize uint64,
	expectedSHA256 string,
) error {
	if !filepath.IsAbs(source) || !filepath.IsAbs(destination) ||
		expectedSize == 0 ||
		expectedSize > 512*1024*1024 ||
		!validLowerSHA256(expectedSHA256) {
		return ErrUnsafeHostCourier
	}
	input, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil ||
		!safeRegularInfo(before, uint32(os.Getuid()), sourceMode) ||
		uint64(before.Size()) != expectedSize {
		return ErrUnsafeHostCourier
	}
	output, err := os.OpenFile(
		destination,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		outputMode,
	)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	failed := true
	defer func() {
		_ = output.Close()
		if failed {
			_ = os.Remove(destination)
		}
	}()
	if output.Chmod(outputMode) != nil {
		return ErrUnsafeHostCourier
	}
	hasher := sha256.New()
	written, err := io.Copy(
		io.MultiWriter(output, hasher),
		io.LimitReader(input, int64(expectedSize)+1),
	)
	if err != nil ||
		uint64(written) != expectedSize ||
		fmtHex(hasher.Sum(nil)) != expectedSHA256 ||
		output.Sync() != nil {
		return ErrUnsafeHostCourier
	}
	outputInfo, err := output.Stat()
	if err != nil ||
		!safeRegularInfo(outputInfo, uint32(os.Getuid()), outputMode) ||
		uint64(outputInfo.Size()) != expectedSize ||
		output.Close() != nil {
		return ErrUnsafeHostCourier
	}
	after, statErr := input.Stat()
	sourceInfo, pathErr := os.Lstat(source)
	if statErr != nil || pathErr != nil ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, sourceInfo) ||
		!before.ModTime().Equal(after.ModTime()) ||
		!after.ModTime().Equal(sourceInfo.ModTime()) ||
		!safeRegularInfo(sourceInfo, uint32(os.Getuid()), sourceMode) {
		return ErrUnsafeHostCourier
	}
	failed = false
	return syncDirectoryPath(filepath.Dir(destination))
}

func requireExactPrivateDirectory(path string, expected []string) error {
	directory, err := openSecureDirectory(path, uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer directory.close()
	return directory.requireExactNames(expected)
}

func validateNoPrivateKeyMaterial(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return ErrUnsafeHostCourier
		}
		name := strings.ToLower(entry.Name())
		if strings.Contains(name, "private") ||
			strings.HasSuffix(name, ".key") ||
			strings.HasPrefix(name, "id_") {
			return ErrUnsafeHostCourier
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeHostCourier
		}
		if info.Size() > 1024*1024 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return ErrUnsafeHostCourier
		}
		defer clear(data)
		if bytes.Contains(data, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) ||
			bytes.Contains(data, []byte("-----BEGIN PRIVATE KEY-----")) ||
			bytes.Contains(data, []byte("-----BEGIN EC PRIVATE KEY-----")) {
			return ErrUnsafeHostCourier
		}
		return nil
	})
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return ErrUnsafeHostCourier
		}
		if entry.IsDir() {
			return syncDirectoryPath(path)
		}
		return nil
	})
}

func syncDirectoryPath(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafeHostCourier
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() || file.Sync() != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}

func sameFileSystem(left string, right string) error {
	leftInfo, leftErr := os.Lstat(left)
	rightInfo, rightErr := os.Lstat(right)
	if leftErr != nil || rightErr != nil {
		return ErrUnsafeHostCourier
	}
	leftStat, leftOK := leftInfo.Sys().(*syscall.Stat_t)
	rightStat, rightOK := rightInfo.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK ||
		leftStat.Dev != rightStat.Dev {
		return ErrUnsafeHostCourier
	}
	return nil
}

func parseMode(value string) (os.FileMode, error) {
	parsed, err := strconv.ParseUint(value, 8, 12)
	if err != nil {
		return 0, ErrUnsafeHostCourier
	}
	return os.FileMode(parsed), nil
}
