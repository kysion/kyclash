package externalpeergueststaging

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	phaseTransactionJournalName  = "journal-v1.json"
	phaseTransactionCompleteName = "complete-v1"
	phaseTransactionPendingName  = "pending"
)

type transactionOutput struct {
	Kind        string `json:"kind"`
	PendingName string `json:"pending_name"`
	Destination string `json:"destination"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Mode        uint32 `json:"mode"`
	ParentMode  uint32 `json:"parent_mode"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	Size        uint64 `json:"size"`
	SHA256      string `json:"sha256"`
}

type phaseTransactionJournal struct {
	SchemaVersion uint8               `json:"schema_version"`
	Role          Role                `json:"role"`
	Phase         Phase               `json:"phase"`
	RuntimeTarget string              `json:"runtime_target"`
	CommandSHA256 string              `json:"command_sha256"`
	Identity      VMIdentity          `json:"identity"`
	Result        Result              `json:"result"`
	Outputs       []transactionOutput `json:"outputs"`
}

type phaseTransaction struct {
	root           string
	state          string
	pending        string
	journalPath    string
	completePath   string
	role           Role
	phase          Phase
	runtimeTarget  string
	commandSHA256  string
	identity       VMIdentity
	uid            uint32
	gid            uint32
	outputs        []transactionOutput
	journalWritten bool
	mutationHook   func(string) error
}

func (transaction *phaseTransaction) abortUncommitted() {
	if transaction == nil || transaction.journalWritten ||
		pathAbsent(transaction.state) {
		return
	}
	_ = removeControlledTree(
		transaction.state, transaction.uid, transaction.gid,
	)
}

func beginPhaseTransaction(
	layout Layout,
	role Role,
	phase Phase,
	runtimeTarget string,
	commandSHA256 string,
	identity VMIdentity,
	uid uint32,
	gid uint32,
	hook func(string) error,
) (*phaseTransaction, *Result, error) {
	if !filepath.IsAbs(layout.TransactionRoot) ||
		filepath.Clean(layout.TransactionRoot) != layout.TransactionRoot ||
		!validSHA256(commandSHA256) ||
		identity.Validate() != nil {
		return nil, nil, ErrGuestStaging
	}
	if err := ensurePrivateTransactionDirectory(
		layout.TransactionRoot, uid, gid,
	); err != nil {
		return nil, nil, err
	}
	state := filepath.Join(
		layout.TransactionRoot,
		fmt.Sprintf("%s-%s-v1", role, phase),
	)
	transaction := &phaseTransaction{
		root:          layout.TransactionRoot,
		state:         state,
		pending:       filepath.Join(state, phaseTransactionPendingName),
		journalPath:   filepath.Join(state, phaseTransactionJournalName),
		completePath:  filepath.Join(state, phaseTransactionCompleteName),
		role:          role,
		phase:         phase,
		runtimeTarget: runtimeTarget,
		commandSHA256: commandSHA256,
		identity:      identity,
		uid:           uid,
		gid:           gid,
		mutationHook:  hook,
	}
	if pathAbsent(state) {
		if err := createTransactionSkeleton(transaction); err != nil {
			return nil, nil, err
		}
		return transaction, nil, nil
	}
	journal, encoded, err := readPhaseTransactionJournal(transaction)
	if err != nil {
		if pathAbsent(transaction.journalPath) {
			if removeControlledTree(state, uid, gid) != nil {
				return nil, nil, ErrGuestStaging
			}
			if err := createTransactionSkeleton(transaction); err != nil {
				return nil, nil, err
			}
			return transaction, nil, nil
		}
		return nil, nil, err
	}
	defer clear(encoded)
	if journal.Role != role ||
		journal.Phase != phase ||
		journal.RuntimeTarget != runtimeTarget ||
		journal.CommandSHA256 != commandSHA256 ||
		!journal.Identity.equalFull(identity) {
		return nil, nil, ErrGuestStaging
	}
	transaction.outputs = append([]transactionOutput(nil), journal.Outputs...)
	transaction.journalWritten = true
	if err := transaction.publish(journal, encoded); err != nil {
		return nil, nil, err
	}
	result := journal.Result
	return transaction, &result, nil
}

func ensurePrivateTransactionDirectory(path string, uid uint32, gid uint32) error {
	if pathAbsent(path) {
		directory, err := ensureCreatedRootDirectory(path, uid, gid, 0o700)
		if err != nil {
			return err
		}
		if directory.close() != nil {
			return ErrGuestStaging
		}
		return syncDirectory(filepath.Dir(path))
	}
	return requireSafeDirectory(path, uid, gid, 0o700)
}

func createTransactionSkeleton(transaction *phaseTransaction) error {
	if transaction == nil || !pathAbsent(transaction.state) {
		return ErrGuestStaging
	}
	state, err := ensureCreatedRootDirectory(
		transaction.state, transaction.uid, transaction.gid, 0o700,
	)
	if err != nil {
		return err
	}
	if state.close() != nil {
		return ErrGuestStaging
	}
	pending, err := ensureCreatedRootDirectory(
		transaction.pending, transaction.uid, transaction.gid, 0o700,
	)
	if err != nil {
		return err
	}
	if pending.close() != nil ||
		syncDirectory(transaction.state) != nil ||
		syncDirectory(transaction.root) != nil {
		return ErrGuestStaging
	}
	return transaction.afterMutation("transaction-skeleton")
}

func (transaction *phaseTransaction) afterMutation(label string) error {
	if transaction != nil && transaction.mutationHook != nil {
		if err := transaction.mutationHook(label); err != nil {
			return err
		}
	}
	return nil
}

func (transaction *phaseTransaction) stageFile(
	destination string,
	data []byte,
	mode os.FileMode,
	parentMode os.FileMode,
) (fileIdentity, error) {
	if transaction == nil || transaction.journalWritten ||
		!filepath.IsAbs(destination) ||
		filepath.Clean(destination) != destination ||
		!pathAbsent(destination) {
		return fileIdentity{}, ErrGuestStaging
	}
	name := fmt.Sprintf("%03d.file", len(transaction.outputs))
	pendingPath := filepath.Join(transaction.pending, name)
	identity, err := createRootFile(
		pendingPath, data, transaction.uid, transaction.gid, mode,
	)
	if err != nil {
		return fileIdentity{}, err
	}
	transaction.outputs = append(transaction.outputs, transactionOutput{
		Kind: "file", PendingName: name, Destination: destination,
		UID: transaction.uid, GID: transaction.gid,
		Mode: uint32(mode.Perm()), ParentMode: uint32(parentMode.Perm()),
		Device: identity.Device, Inode: identity.Inode,
		Size: identity.Size, SHA256: identity.SHA256,
	})
	if err := transaction.afterMutation("stage-file:" + filepath.Base(destination)); err != nil {
		return fileIdentity{}, err
	}
	return identity, nil
}

func (transaction *phaseTransaction) stageDirectory(
	destination string,
	mode os.FileMode,
	parentMode os.FileMode,
	populate func(string) error,
) (transactionOutput, error) {
	if transaction == nil || transaction.journalWritten ||
		populate == nil ||
		!filepath.IsAbs(destination) ||
		filepath.Clean(destination) != destination ||
		!pathAbsent(destination) {
		return transactionOutput{}, ErrGuestStaging
	}
	name := fmt.Sprintf("%03d.tree", len(transaction.outputs))
	pendingPath := filepath.Join(transaction.pending, name)
	directory, err := ensureCreatedRootDirectory(
		pendingPath, transaction.uid, transaction.gid, mode,
	)
	if err != nil {
		return transactionOutput{}, err
	}
	if directory.close() != nil {
		return transactionOutput{}, ErrGuestStaging
	}
	if err := populate(pendingPath); err != nil {
		return transactionOutput{}, err
	}
	if err := syncTreeDirectories(pendingPath); err != nil {
		return transactionOutput{}, err
	}
	digest, size, rootIdentity, err := digestControlledTree(
		pendingPath, transaction.uid, transaction.gid,
	)
	if err != nil {
		return transactionOutput{}, err
	}
	output := transactionOutput{
		Kind: "tree", PendingName: name, Destination: destination,
		UID: transaction.uid, GID: transaction.gid,
		Mode: uint32(mode.Perm()), ParentMode: uint32(parentMode.Perm()),
		Device: rootIdentity.Device, Inode: rootIdentity.Inode,
		Size: size, SHA256: digest,
	}
	transaction.outputs = append(transaction.outputs, output)
	if err := transaction.afterMutation("stage-tree:" + filepath.Base(destination)); err != nil {
		return transactionOutput{}, err
	}
	return output, nil
}

func (transaction *phaseTransaction) commit(
	result Result,
	finalIdentity VMIdentity,
) (Result, error) {
	if transaction == nil || transaction.journalWritten ||
		len(transaction.outputs) == 0 ||
		finalIdentity.Validate() != nil ||
		result.Role != transaction.role ||
		result.Phase != transaction.phase ||
		!filepath.IsAbs(result.ReviewPath) ||
		!validSHA256(result.ReviewSHA) {
		return Result{}, ErrGuestStaging
	}
	transaction.identity = finalIdentity
	journal := phaseTransactionJournal{
		SchemaVersion: 1,
		Role:          transaction.role,
		Phase:         transaction.phase,
		RuntimeTarget: transaction.runtimeTarget,
		CommandSHA256: transaction.commandSHA256,
		Identity:      finalIdentity,
		Result:        result,
		Outputs:       append([]transactionOutput(nil), transaction.outputs...),
	}
	encoded, err := encodePhaseTransactionJournal(journal)
	if err != nil {
		return Result{}, err
	}
	defer clear(encoded)
	if err := atomicCreateTransactionFile(
		transaction.state,
		transaction.journalPath,
		".journal.pending",
		encoded,
		transaction.uid,
		transaction.gid,
		0o600,
	); err != nil {
		return Result{}, err
	}
	transaction.journalWritten = true
	if err := transaction.afterMutation("journal-committed"); err != nil {
		return Result{}, err
	}
	if err := transaction.publish(journal, encoded); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (transaction *phaseTransaction) publish(
	journal phaseTransactionJournal,
	journalBytes []byte,
) error {
	if transaction == nil ||
		validatePhaseTransactionJournal(journal) != nil ||
		journal.Role != transaction.role ||
		journal.Phase != transaction.phase {
		return ErrGuestStaging
	}
	for _, output := range journal.Outputs {
		pendingPath := filepath.Join(transaction.pending, output.PendingName)
		pendingExists := !pathAbsent(pendingPath)
		destinationExists := !pathAbsent(output.Destination)
		switch {
		case pendingExists && !destinationExists:
			if err := ensureTransactionDestinationParent(
				filepath.Dir(output.Destination),
				output.UID,
				output.GID,
				os.FileMode(output.ParentMode),
			); err != nil {
				return err
			}
			if err := verifyTransactionOutput(pendingPath, output); err != nil {
				return err
			}
			if err := os.Rename(pendingPath, output.Destination); err != nil {
				return ErrGuestStaging
			}
			if err := syncDirectory(filepath.Dir(output.Destination)); err != nil {
				return err
			}
			if err := transaction.afterMutation(
				"publish:" + filepath.Base(output.Destination),
			); err != nil {
				return err
			}
			if err := verifyTransactionOutput(output.Destination, output); err != nil {
				return err
			}
		case !pendingExists && destinationExists:
			if err := verifyTransactionOutput(output.Destination, output); err != nil {
				return err
			}
		default:
			return ErrGuestStaging
		}
	}
	expected := hashHex(journalBytes) + "\n"
	if pathAbsent(transaction.completePath) {
		if err := atomicCreateTransactionFile(
			transaction.state,
			transaction.completePath,
			".complete.pending",
			[]byte(expected),
			transaction.uid,
			transaction.gid,
			0o600,
		); err != nil {
			return err
		}
		if err := transaction.afterMutation("transaction-complete"); err != nil {
			return err
		}
	} else {
		data, _, err := readSafeFile(
			transaction.completePath,
			transaction.uid,
			transaction.gid,
			0o600,
			128,
		)
		defer clear(data)
		if err != nil || string(data) != expected {
			return ErrGuestStaging
		}
	}
	return nil
}

func ensureTransactionDestinationParent(
	parent string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) error {
	if pathAbsent(parent) {
		directory, err := ensureCreatedRootDirectory(parent, uid, gid, mode)
		if err != nil {
			return err
		}
		if directory.close() != nil ||
			syncDirectory(filepath.Dir(parent)) != nil {
			return ErrGuestStaging
		}
		return nil
	}
	directory, err := openStableDirectory(parent, uid, gid, mode)
	if err != nil {
		return err
	}
	return directory.close()
}

func verifyTransactionOutput(path string, output transactionOutput) error {
	if output.Kind == "file" {
		data, identity, err := readSafeFile(
			path,
			output.UID,
			output.GID,
			os.FileMode(output.Mode),
			maximumAppTreeSize,
		)
		defer clear(data)
		if err != nil ||
			identity.Device != output.Device ||
			identity.Inode != output.Inode ||
			identity.Size != output.Size ||
			identity.SHA256 != output.SHA256 {
			return ErrGuestStaging
		}
		return nil
	}
	if output.Kind != "tree" {
		return ErrGuestStaging
	}
	digest, size, identity, err := digestControlledTree(
		path, output.UID, output.GID,
	)
	if err != nil ||
		identity.Device != output.Device ||
		identity.Inode != output.Inode ||
		identity.Mode != output.Mode ||
		size != output.Size ||
		digest != output.SHA256 {
		return ErrGuestStaging
	}
	return nil
}

func encodePhaseTransactionJournal(
	journal phaseTransactionJournal,
) ([]byte, error) {
	if validatePhaseTransactionJournal(journal) != nil {
		return nil, ErrGuestStaging
	}
	encoded, err := json.Marshal(journal)
	if err != nil || len(encoded)+1 > sshBootstrapMaxFile {
		return nil, ErrGuestStaging
	}
	return append(encoded, '\n'), nil
}

func readPhaseTransactionJournal(
	transaction *phaseTransaction,
) (phaseTransactionJournal, []byte, error) {
	if transaction == nil ||
		requireSafeDirectory(
			transaction.state, transaction.uid, transaction.gid, 0o700,
		) != nil {
		return phaseTransactionJournal{}, nil, ErrGuestStaging
	}
	data, _, err := readSafeFile(
		transaction.journalPath,
		transaction.uid,
		transaction.gid,
		0o600,
		sshBootstrapMaxFile,
	)
	if err != nil {
		return phaseTransactionJournal{}, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal phaseTransactionJournal
	if decoder.Decode(&journal) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		validatePhaseTransactionJournal(journal) != nil {
		clear(data)
		return phaseTransactionJournal{}, nil, ErrGuestStaging
	}
	return journal, data, nil
}

func validatePhaseTransactionJournal(journal phaseTransactionJournal) error {
	if journal.SchemaVersion != 1 ||
		(journal.Role != ClientRole && journal.Role != PeerRole) ||
		(journal.Phase != LayerAStage &&
			journal.Phase != LayerASSHBootstrap &&
			journal.Phase != LayerBPrepare &&
			journal.Phase != LayerBPin) ||
		!validSHA256(journal.CommandSHA256) ||
		journal.Identity.Validate() != nil ||
		journal.Result.Role != journal.Role ||
		journal.Result.Phase != journal.Phase ||
		!filepath.IsAbs(journal.Result.ReviewPath) ||
		!validSHA256(journal.Result.ReviewSHA) ||
		len(journal.Outputs) == 0 ||
		len(journal.Outputs) > 32 {
		return ErrGuestStaging
	}
	expectedTarget := map[Role]string{
		ClientRole: "kyclash-macos-lab-work",
		PeerRole:   "kyclash-macos-lab-peer",
	}[journal.Role]
	if journal.RuntimeTarget != expectedTarget {
		return ErrGuestStaging
	}
	destinations := make(map[string]struct{}, len(journal.Outputs))
	pending := make(map[string]struct{}, len(journal.Outputs))
	for _, output := range journal.Outputs {
		if (output.Kind != "file" && output.Kind != "tree") ||
			!fixedBaseName(output.PendingName) ||
			!filepath.IsAbs(output.Destination) ||
			filepath.Clean(output.Destination) != output.Destination ||
			output.Mode == 0 ||
			output.ParentMode == 0 ||
			output.Device == 0 ||
			output.Inode == 0 ||
			!validSHA256(output.SHA256) {
			return ErrGuestStaging
		}
		if _, exists := destinations[output.Destination]; exists {
			return ErrGuestStaging
		}
		if _, exists := pending[output.PendingName]; exists {
			return ErrGuestStaging
		}
		destinations[output.Destination] = struct{}{}
		pending[output.PendingName] = struct{}{}
	}
	return nil
}

func atomicCreateTransactionFile(
	parent string,
	finalPath string,
	temporaryName string,
	data []byte,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) error {
	if filepath.Dir(finalPath) != parent ||
		!fixedBaseName(temporaryName) ||
		!pathAbsent(finalPath) {
		return ErrGuestStaging
	}
	temporary := filepath.Join(parent, temporaryName)
	if !pathAbsent(temporary) {
		return ErrGuestStaging
	}
	if _, err := createRootFile(temporary, data, uid, gid, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, finalPath); err != nil {
		return ErrGuestStaging
	}
	return syncDirectory(parent)
}

func digestControlledTree(
	root string,
	uid uint32,
	gid uint32,
) (string, uint64, fileIdentity, error) {
	rootInfo, err := os.Lstat(root)
	rootIdentity, identityErr := identityFromInfo(rootInfo)
	if err != nil ||
		identityErr != nil ||
		!rootInfo.IsDir() ||
		rootInfo.Mode()&os.ModeSymlink != 0 ||
		rootIdentity.UID != uid ||
		rootIdentity.GID != gid ||
		rootInfo.Mode().Perm()&0o022 != 0 {
		return "", 0, fileIdentity{}, ErrGuestStaging
	}
	hasher := sha256.New()
	var total uint64
	var entries int
	var visit func(string, string, int) error
	visit = func(directory string, prefix string, depth int) error {
		if depth > maximumAppDepth {
			return ErrGuestStaging
		}
		children, err := os.ReadDir(directory)
		if err != nil {
			return ErrGuestStaging
		}
		sort.Slice(children, func(left, right int) bool {
			return children[left].Name() < children[right].Name()
		})
		for _, child := range children {
			entries++
			if entries > maximumAppEntries || !fixedBaseName(child.Name()) {
				return ErrGuestStaging
			}
			relative := child.Name()
			if prefix != "" {
				relative = prefix + "/" + child.Name()
			}
			path := filepath.Join(directory, child.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrGuestStaging
			}
			identity, err := identityFromInfo(info)
			if err != nil || identity.UID != uid || identity.GID != gid {
				return ErrGuestStaging
			}
			if info.IsDir() {
				if info.Mode().Perm()&0o022 != 0 {
					return ErrGuestStaging
				}
				_, _ = fmt.Fprintf(
					hasher, "d:%d:%s\x00", info.Mode().Perm(), relative,
				)
				if err := visit(path, relative, depth+1); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() || identity.Links != 1 ||
				info.Size() < 0 || info.Size() > maximumAppFileSize {
				return ErrGuestStaging
			}
			data, err := os.ReadFile(path)
			if err != nil || int64(len(data)) != info.Size() {
				clear(data)
				return ErrGuestStaging
			}
			total += uint64(len(data))
			if total > maximumAppTreeSize {
				clear(data)
				return ErrGuestStaging
			}
			_, _ = fmt.Fprintf(
				hasher,
				"f:%d:%d:%s\x00",
				info.Mode().Perm(),
				len(data),
				relative,
			)
			_, _ = hasher.Write(data)
			clear(data)
		}
		return nil
	}
	if err := visit(root, "", 0); err != nil || entries == 0 {
		return "", 0, fileIdentity{}, ErrGuestStaging
	}
	return hex.EncodeToString(hasher.Sum(nil)), total, rootIdentity, nil
}

func syncTreeDirectories(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrGuestStaging
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return ErrGuestStaging
	}
	sort.Slice(directories, func(left, right int) bool {
		return strings.Count(directories[left], string(os.PathSeparator)) >
			strings.Count(directories[right], string(os.PathSeparator))
	})
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func removeControlledTree(path string, uid uint32, gid uint32) error {
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return ErrGuestStaging
	}
	identity, err := identityFromInfo(info)
	if err != nil || identity.UID != uid || identity.GID != gid {
		return ErrGuestStaging
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return ErrGuestStaging
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		childInfo, err := os.Lstat(child)
		if err != nil || childInfo.Mode()&os.ModeSymlink != 0 {
			return ErrGuestStaging
		}
		childIdentity, err := identityFromInfo(childInfo)
		if err != nil ||
			childIdentity.UID != uid ||
			childIdentity.GID != gid {
			return ErrGuestStaging
		}
		if childInfo.IsDir() {
			if err := removeControlledTree(child, uid, gid); err != nil {
				return err
			}
		} else {
			if !childInfo.Mode().IsRegular() || childIdentity.Links != 1 ||
				os.Remove(child) != nil {
				return ErrGuestStaging
			}
		}
	}
	if os.Remove(path) != nil {
		return ErrGuestStaging
	}
	return syncDirectory(filepath.Dir(path))
}
