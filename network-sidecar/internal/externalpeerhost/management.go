package externalpeerhost

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kysion/kyclash/network-sidecar/internal/externalpeer"
	"golang.org/x/crypto/ssh"
)

const managementConsoleUser = "supen"

type roleContract struct {
	role          string
	vmName        string
	facts         externalpeer.CourierVMFacts
	consoleUID    uint32
	privateKey    string
	knownHosts    string
	keyWitness    fileWitness
	publicWitness fileWitness
	knownWitness  fileWitness
}

type managementStore struct {
	directory       *secureDirectory
	publicDirectory *secureDirectory
	client          roleContract
	peer            roleContract
}

func openManagementStore(
	layout Layout,
	config externalpeer.PeerSupervisorConfig,
) (*managementStore, error) {
	if config.Validate() != nil {
		return nil, ErrUnsafeHostCourier
	}
	directory, err := openSecureDirectory(layout.Management, uint32(os.Getuid()))
	if err != nil {
		return nil, err
	}
	var publicDirectory *secureDirectory
	fail := func() (*managementStore, error) {
		_ = directory.close()
		if publicDirectory != nil {
			_ = publicDirectory.close()
		}
		return nil, ErrUnsafeHostCourier
	}
	if directory.requireExactNames(managementNames) != nil {
		return fail()
	}
	publicDirectory, err = openSecureDirectory(
		layout.ManagementPublic,
		uint32(os.Getuid()),
	)
	if err != nil ||
		publicDirectory.requireExactNames(managementPublicNames) != nil {
		if publicDirectory != nil {
			_ = publicDirectory.close()
		}
		return fail()
	}
	clientFacts, err := config.Client.CourierFacts()
	if err != nil {
		return fail()
	}
	peerFacts, err := config.Peer.CourierFacts()
	if err != nil {
		return fail()
	}
	result := &managementStore{
		directory:       directory,
		publicDirectory: publicDirectory,
	}
	for _, item := range []struct {
		destination *roleContract
		role        string
		vmName      string
		facts       externalpeer.CourierVMFacts
		keyName     string
		publicName  string
		knownName   string
	}{
		{
			&result.client, "client", externalpeer.ClientVMName, clientFacts,
			ClientManagementKeyName, ClientManagementPublicName,
			ClientKnownHostsName,
		},
		{
			&result.peer, "peer", externalpeer.PeerVMName, peerFacts,
			PeerManagementKeyName, PeerManagementPublicName,
			PeerKnownHostsName,
		},
	} {
		keyBlob, err := directory.readStableFile(
			item.keyName,
			maximumManagementKeyBytes,
			nil,
		)
		if err != nil {
			return fail()
		}
		publicBlob, err := publicDirectory.readStableFile(
			item.publicName,
			4096,
			nil,
		)
		if err != nil {
			clear(keyBlob.bytes)
			return fail()
		}
		expectedPublic, err := rawManagementPublicFromPrivate(keyBlob.bytes)
		clear(keyBlob.bytes)
		if err != nil || !equalBytes(expectedPublic, publicBlob.bytes) {
			clear(expectedPublic)
			clear(publicBlob.bytes)
			return fail()
		}
		clear(expectedPublic)
		clear(publicBlob.bytes)
		knownBlob, err := directory.readStableFile(item.knownName, 4096, nil)
		if err != nil {
			return fail()
		}
		if validateKnownHosts(
			knownBlob.bytes,
			item.vmName,
			item.facts.SSHHostFingerprint,
		) != nil {
			clear(knownBlob.bytes)
			return fail()
		}
		clear(knownBlob.bytes)
		*item.destination = roleContract{
			role:          item.role,
			vmName:        item.vmName,
			facts:         item.facts,
			consoleUID:    config.ConsoleUID,
			privateKey:    filepath.Join(layout.Management, item.keyName),
			knownHosts:    filepath.Join(layout.Management, item.knownName),
			keyWitness:    keyBlob.witness,
			publicWitness: publicBlob.witness,
			knownWitness:  knownBlob.witness,
		}
	}
	if result.revalidate() != nil {
		result.close()
		return nil, ErrUnsafeHostCourier
	}
	return result, nil
}

func (store *managementStore) close() {
	if store == nil {
		return
	}
	_ = store.directory.close()
	_ = store.publicDirectory.close()
	*store = managementStore{}
}

func (store *managementStore) revalidate() error {
	if store == nil || store.directory == nil ||
		store.publicDirectory == nil ||
		store.directory.revalidate() != nil ||
		store.publicDirectory.revalidate() != nil {
		return ErrUnsafeHostCourier
	}
	for _, role := range []*roleContract{&store.client, &store.peer} {
		if role.keyWitness.revalidate() != nil ||
			role.publicWitness.revalidate() != nil ||
			role.knownWitness.revalidate() != nil {
			return ErrUnsafeHostCourier
		}
	}
	return nil
}

func (store *managementStore) role(value string) (roleContract, error) {
	if store == nil || store.revalidate() != nil {
		return roleContract{}, ErrUnsafeHostCourier
	}
	switch value {
	case "client":
		return store.client, nil
	case "peer":
		return store.peer, nil
	default:
		return roleContract{}, ErrUnsafeHostCourier
	}
}

func validateKnownHosts(
	data []byte,
	expectedAlias string,
	expectedFingerprint string,
) error {
	if len(data) == 0 || len(data) > 4096 ||
		!strings.HasSuffix(string(data), "\n") ||
		strings.Count(string(data), "\n") != 1 {
		return ErrUnsafeHostCourier
	}
	fields := strings.Fields(strings.TrimSuffix(string(data), "\n"))
	if len(fields) != 3 ||
		fields[0] != expectedAlias ||
		fields[1] != ssh.KeyAlgoED25519 {
		return ErrUnsafeHostCourier
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(
		[]byte(fields[1] + " " + fields[2] + "\n"),
	)
	if err != nil ||
		publicKey.Type() != ssh.KeyAlgoED25519 ||
		ssh.FingerprintSHA256(publicKey) != expectedFingerprint {
		return ErrUnsafeHostCourier
	}
	return nil
}
