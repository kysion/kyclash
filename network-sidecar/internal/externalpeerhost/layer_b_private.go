package externalpeerhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"github.com/kysion/kyclash/network-sidecar/internal/externalpeergueststaging"
)

func buildLayerBConfig(
	client *guestReviewSet,
	peer *guestReviewSet,
	clientIP netip.Addr,
	peerIP netip.Addr,
) (externalpeer.PeerSupervisorConfig, []byte, error) {
	if client == nil || peer == nil ||
		client.role != "client" || peer.role != "peer" ||
		client.revalidate() != nil || peer.revalidate() != nil ||
		!clientIP.Is4() || !clientIP.IsPrivate() ||
		!peerIP.Is4() || !peerIP.IsPrivate() ||
		clientIP == peerIP ||
		client.management.ConsoleUID == 0 ||
		client.management.ConsoleUID != peer.management.ConsoleUID ||
		client.management.ConsoleGID != peer.management.ConsoleGID ||
		equalFoldUUID(
			client.identity.Identity.PlatformUUID,
			peer.identity.Identity.PlatformUUID,
		) ||
		equalMACText(
			client.identity.Identity.En0MAC,
			peer.identity.Identity.En0MAC,
		) ||
		client.identity.Identity.SSHHostKeyFingerprint ==
			peer.identity.Identity.SSHHostKeyFingerprint {
		return externalpeer.PeerSupervisorConfig{}, nil, ErrUnsafeHostCourier
	}
	config := externalpeer.PeerSupervisorConfig{
		SchemaVersion: externalpeer.SchemaVersion,
		ConsoleUID:    client.management.ConsoleUID,
		ConsoleGID:    client.management.ConsoleGID,
		PeerChildUID:  502,
		PeerChildGID:  20,
		Client: externalpeer.SupervisorVMConfig{
			Role: "client", VMName: externalpeer.ClientVMName,
			PlatformUUID: client.identity.Identity.PlatformUUID,
			SSHHostFingerprint: client.identity.Identity.
				SSHHostKeyFingerprint,
			MAC:  client.identity.Identity.En0MAC,
			IPv4: clientIP.String(),
		},
		Peer: externalpeer.SupervisorVMConfig{
			Role: "peer", VMName: externalpeer.PeerVMName,
			PlatformUUID: peer.identity.Identity.PlatformUUID,
			SSHHostFingerprint: peer.identity.Identity.
				SSHHostKeyFingerprint,
			MAC:  peer.identity.Identity.En0MAC,
			IPv4: peerIP.String(),
		},
	}
	encoded, err := encodeCanonicalHostJSON(config)
	if err != nil || config.Validate() != nil {
		clear(encoded)
		return externalpeer.PeerSupervisorConfig{}, nil, ErrUnsafeHostCourier
	}
	decoded, err := externalpeer.DecodePeerSupervisorConfig(encoded)
	if err != nil || decoded != config {
		clear(encoded)
		return externalpeer.PeerSupervisorConfig{}, nil, ErrUnsafeHostCourier
	}
	return config, encoded, nil
}

func buildRunTicketExpectation(
	builds externalPeerBuildInputs,
	configBytes []byte,
) (externalpeer.RunTicketExpectation, []byte, error) {
	if len(configBytes) == 0 ||
		len(configBytes) > externalpeer.MaxDescriptorSize {
		return externalpeer.RunTicketExpectation{}, nil, ErrUnsafeHostCourier
	}
	main := builds.appManifest.MainExecutable
	entries := map[string]externalpeer.ArtifactDigest{
		"app": {
			Name: "app", Length: main.ByteLength, SHA256: main.SHA256,
		},
		"peer-config": {
			Name: "peer-config", Length: uint64(len(configBytes)),
			SHA256: hashBytes(configBytes),
		},
	}
	for ticketName, artifactName := range map[string]string{
		"client-supervisor":     "kyclash-vm-external-peer-lab-supervisor",
		"client-harness":        "kyclash-vm-external-peer-lab-harness",
		"peer-supervisor":       "kyclash-vm-external-peer-lab-peer-root-supervisor",
		"peer-child":            "kyclash-vm-external-peer-lab-peer",
		"listener-auditor":      "kyclash-vm-external-peer-lab-listener-auditor",
		"forced-command-helper": "kyclash-vm-external-peer-lab-forced-command",
	} {
		artifact, exists := builds.artifacts[artifactName]
		if !exists {
			return externalpeer.RunTicketExpectation{}, nil,
				ErrUnsafeHostCourier
		}
		entries[ticketName] = externalpeer.ArtifactDigest{
			Name: ticketName, Length: artifact.ByteLength,
			SHA256: artifact.SHA256,
		}
	}
	expectation := externalpeer.RunTicketExpectation{
		SchemaVersion: externalpeer.SchemaVersion,
		Files: make(
			[]externalpeer.ArtifactDigest,
			0,
			len(externalpeer.RunTicketArtifactNames),
		),
	}
	for _, name := range externalpeer.RunTicketArtifactNames {
		value, exists := entries[name]
		if !exists {
			return externalpeer.RunTicketExpectation{}, nil,
				ErrUnsafeHostCourier
		}
		expectation.Files = append(expectation.Files, value)
	}
	encoded, err := encodeCanonicalHostJSON(expectation)
	if err != nil || expectation.Validate() != nil {
		clear(encoded)
		return externalpeer.RunTicketExpectation{}, nil, ErrUnsafeHostCourier
	}
	decoded, err := externalpeer.DecodeRunTicketExpectation(encoded)
	if err != nil || !equalExpectation(decoded, expectation) {
		clear(encoded)
		return externalpeer.RunTicketExpectation{}, nil, ErrUnsafeHostCourier
	}
	return expectation, encoded, nil
}

func ensureLayerBWorkspace(
	layout Layout,
	config []byte,
	expectation []byte,
) error {
	validate := func(root string) error {
		if requireExactPrivateDirectory(root, []string{
			ControlDirectoryName,
			ClientDirectoryName,
			PeerDirectoryName,
			EnvelopeDirectoryName,
		}) != nil {
			return ErrUnsafeHostCourier
		}
		control := filepath.Join(root, ControlDirectoryName)
		if requireExactPrivateDirectory(control, controlInputNames) != nil {
			return ErrUnsafeHostCourier
		}
		for _, directory := range []string{
			ClientDirectoryName,
			PeerDirectoryName,
			EnvelopeDirectoryName,
		} {
			if requireExactPrivateDirectory(
				filepath.Join(root, directory),
				nil,
			) != nil {
				return ErrUnsafeHostCourier
			}
		}
		for name, expected := range map[string][]byte{
			PeerConfigName:        config,
			TicketExpectationName: expectation,
		} {
			data, err := readOwnedRegularFile(
				filepath.Join(control, name),
				secureFileMode,
				externalpeer.MaxDescriptorSize,
			)
			if err != nil || !bytes.Equal(data, expected) {
				clear(data)
				return ErrUnsafeHostCourier
			}
			clear(data)
		}
		return nil
	}
	populate := func(root string) error {
		for _, name := range []string{
			ControlDirectoryName,
			ClientDirectoryName,
			PeerDirectoryName,
			EnvelopeDirectoryName,
		} {
			if os.Mkdir(filepath.Join(root, name), 0o700) != nil {
				return ErrUnsafeHostCourier
			}
		}
		control, err := openSecureDirectory(
			filepath.Join(root, ControlDirectoryName),
			uint32(os.Getuid()),
		)
		if err != nil {
			return err
		}
		defer control.close()
		if _, err := control.createExactFile(PeerConfigName, config); err != nil {
			return err
		}
		if _, err := control.createExactFile(
			TicketExpectationName,
			expectation,
		); err != nil {
			return err
		}
		return syncTree(root)
	}
	if err := publishPrivateDirectory(
		layout.PrivateRoot,
		layout.Workspace,
		WorkspaceDirectoryName,
		populate,
		validate,
	); err != nil {
		return err
	}
	workspace, err := openHostWorkspace(layout)
	if err != nil {
		return err
	}
	defer workspace.close()
	if !bytes.Equal(workspace.controlData[0].bytes, config) ||
		!bytes.Equal(workspace.controlData[1].bytes, expectation) {
		return ErrUnsafeHostCourier
	}
	return nil
}

func ensureManagementReview(
	layout Layout,
	client *guestReviewSet,
	peer *guestReviewSet,
) error {
	type reviewCopy struct {
		source string
		target string
		size   uint64
		sha256 string
	}
	copies := make([]reviewCopy, 0, len(managementReviewNames))
	for _, value := range []struct {
		review *guestReviewSet
		source string
		target string
	}{
		{client, externalpeergueststaging.SSHHostPublicKeyName, ClientHostPublicReviewName},
		{client, externalpeergueststaging.SSHHostFingerprintName, ClientHostFingerprintName},
		{client, externalpeergueststaging.SSHBootstrapWitnessName, ClientSSHBootstrapWitnessName},
		{peer, externalpeergueststaging.SSHHostPublicKeyName, PeerHostPublicReviewName},
		{peer, externalpeergueststaging.SSHHostFingerprintName, PeerHostFingerprintName},
		{peer, externalpeergueststaging.SSHBootstrapWitnessName, PeerSSHBootstrapWitnessName},
	} {
		blob, err := value.review.blob(value.source)
		if err != nil {
			return err
		}
		copies = append(copies, reviewCopy{
			source: filepath.Join(value.review.root, value.source),
			target: value.target,
			size:   uint64(len(blob.bytes)),
			sha256: hashBytes(blob.bytes),
		})
	}
	validate := func(root string) error {
		if requireExactPrivateDirectory(root, managementReviewNames) != nil {
			return ErrUnsafeHostCourier
		}
		for _, value := range copies {
			digest, size, err := hashStableFile(
				filepath.Join(root, value.target),
				uint32(os.Getuid()),
				secureFileMode,
				maximumHostArtifactBytes,
			)
			if err != nil || size != value.size || digest != value.sha256 {
				return ErrUnsafeHostCourier
			}
		}
		return nil
	}
	populate := func(root string) error {
		if client.revalidate() != nil || peer.revalidate() != nil {
			return ErrUnsafeHostCourier
		}
		for _, value := range copies {
			if err := copyStablePublicFile(
				value.source,
				filepath.Join(root, value.target),
				secureFileMode,
				secureFileMode,
				value.size,
				value.sha256,
			); err != nil {
				return err
			}
		}
		return syncDirectoryPath(root)
	}
	return publishPrivateDirectory(
		layout.PrivateRoot,
		layout.ManagementReview,
		ManagementReviewName,
		populate,
		validate,
	)
}

func managementHostKeysPinned(
	layout Layout,
) (bool, error) {
	directory, err := openSecureDirectory(
		layout.Management,
		uint32(os.Getuid()),
	)
	if err != nil {
		return false, err
	}
	defer directory.close()
	if directory.requireExactNames(managementNames) == nil {
		return true, nil
	}
	if directory.requireExactNames(managementPrivateNames) == nil {
		return false, nil
	}
	return false, ErrUnsafeHostCourier
}

func openPinnedManagementStore(
	layout Layout,
	config externalpeer.PeerSupervisorConfig,
) (*managementStore, error) {
	pinned, err := managementHostKeysPinned(layout)
	if err != nil || !pinned {
		return nil, ErrUnsafeHostCourier
	}
	return openManagementStore(layout, config)
}

func publishPrivateDirectory(
	parentPath string,
	finalPath string,
	name string,
	populate func(string) error,
	validate func(string) error,
) error {
	if !filepath.IsAbs(parentPath) || !filepath.IsAbs(finalPath) ||
		filepath.Dir(finalPath) != parentPath ||
		filepath.Base(finalPath) != name ||
		!fixedBaseName(name) ||
		populate == nil || validate == nil {
		return ErrUnsafeHostCourier
	}
	parent, err := openSecureDirectory(parentPath, uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer parent.close()
	if _, err := os.Lstat(finalPath); err == nil {
		return validate(finalPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafeHostCourier
	}
	pending, err := os.MkdirTemp(parentPath, "."+name+".pending.")
	if err != nil || os.Chmod(pending, 0o700) != nil {
		return ErrUnsafeHostCourier
	}
	present := true
	defer func() {
		if present {
			_ = os.RemoveAll(pending)
		}
	}()
	if populate(pending) != nil ||
		validate(pending) != nil ||
		syncDirectoryPath(pending) != nil ||
		parent.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	if err := renameDirectoryNoReplace(pending, finalPath); err != nil {
		return err
	}
	present = false
	if parent.file.Sync() != nil ||
		parent.revalidate() != nil ||
		validate(finalPath) != nil {
		return ErrUnsafeHostCourier
	}
	return nil
}

func encodeCanonicalHostJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > externalpeer.MaxDescriptorSize {
		clear(encoded)
		return nil, ErrUnsafeHostCourier
	}
	return append(encoded, '\n'), nil
}

func equalExpectation(
	left externalpeer.RunTicketExpectation,
	right externalpeer.RunTicketExpectation,
) bool {
	if left.SchemaVersion != right.SchemaVersion ||
		len(left.Files) != len(right.Files) {
		return false
	}
	for index := range left.Files {
		if left.Files[index] != right.Files[index] {
			return false
		}
	}
	return true
}

func equalMACText(left string, right string) bool {
	leftMAC, leftErr := net.ParseMAC(left)
	rightMAC, rightErr := net.ParseMAC(right)
	return leftErr == nil && rightErr == nil &&
		bytes.Equal(leftMAC, rightMAC)
}
