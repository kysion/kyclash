package externalpeergueststaging

import (
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

type appCopyBudget struct {
	entries int
	bytes   int64
}

// populateAppBundle fills a transaction-owned, otherwise empty destination.
// Publication to /Applications is performed only after the complete tree has
// been hashed, synced, journaled, and atomically renamed by phaseTransaction.
func populateAppBundle(
	input *stableDirectory,
	destinationPath string,
	rootUID uint32,
	rootGID uint32,
	manifest appTreeManifest,
) error {
	source, err := openStableAppDirectory(input, AppInputName)
	if err != nil {
		return err
	}
	defer source.close()
	if source.mode != inputDirectoryMode ||
		!filepath.IsAbs(destinationPath) ||
		filepath.Clean(destinationPath) != destinationPath {
		return ErrGuestStaging
	}
	if err := verifyStableAppTree(
		source,
		manifest,
		inputDirectoryMode,
	); err != nil {
		return err
	}
	destination, err := openStableDirectory(
		destinationPath, rootUID, rootGID, 0o755,
	)
	if err != nil {
		return err
	}
	defer destination.close()
	budget := &appCopyBudget{}
	if err := copyAppDirectory(
		source, destination, rootUID, rootGID, 0, budget,
	); err != nil {
		return err
	}
	if source.revalidate() != nil ||
		destination.revalidate() != nil ||
		budget.entries == 0 ||
		budget.entries > maximumAppEntries ||
		budget.bytes <= 0 ||
		budget.bytes > maximumAppTreeSize {
		return ErrGuestStaging
	}
	if err := verifyStableAppTree(
		destination,
		manifest,
		0o755,
	); err != nil {
		return err
	}
	for _, required := range []string{
		filepath.Join(destinationPath, "Contents", "Info.plist"),
		filepath.Join(destinationPath, "Contents", "MacOS", "clash-verge"),
	} {
		if _, err := os.Lstat(required); err != nil {
			return ErrGuestStaging
		}
	}
	executable, err := readStableRootFile(
		filepath.Join(destinationPath, "Contents", "MacOS", "clash-verge"),
		rootUID, rootGID, 0o755, maximumExecutableSize,
	)
	if err != nil {
		return err
	}
	defer executable.directory.close()
	defer executable.clear()
	if validateThinArm64(executable.bytes) != nil {
		return ErrGuestStaging
	}
	return executable.revalidate()
}

func copyAppDirectory(
	source *stableDirectory,
	destination *stableDirectory,
	rootUID uint32,
	rootGID uint32,
	depth int,
	budget *appCopyBudget,
) error {
	if source == nil || destination == nil || budget == nil ||
		depth > maximumAppDepth ||
		source.revalidate() != nil ||
		destination.revalidate() != nil {
		return ErrGuestStaging
	}
	entries, err := source.file.ReadDir(-1)
	if err != nil {
		return ErrGuestStaging
	}
	if _, err := source.file.Seek(0, io.SeekStart); err != nil {
		return ErrGuestStaging
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name() < entries[right].Name()
	})
	for _, entry := range entries {
		name := entry.Name()
		if !fixedBaseName(name) {
			return ErrGuestStaging
		}
		budget.entries++
		if budget.entries > maximumAppEntries {
			return ErrGuestStaging
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrGuestStaging
		}
		if entry.IsDir() {
			childSource, err := openStableAppDirectory(source, name)
			if err != nil {
				return err
			}
			if err := createChildRootDirectory(
				destination, name, rootUID, rootGID, 0o755,
			); err != nil {
				_ = childSource.close()
				return err
			}
			childDestination, err := openStableDirectory(
				filepath.Join(destination.path, name),
				rootUID, rootGID, 0o755,
			)
			if err != nil {
				_ = childSource.close()
				return err
			}
			copyErr := copyAppDirectory(
				childSource, childDestination,
				rootUID, rootGID, depth+1, budget,
			)
			closeSourceErr := childSource.close()
			closeDestinationErr := childDestination.close()
			if copyErr != nil ||
				closeSourceErr != nil ||
				closeDestinationErr != nil {
				return ErrGuestStaging
			}
			continue
		}
		if !entry.Type().IsRegular() {
			return ErrGuestStaging
		}
		if err := copyAppRegularFile(
			source, destination, name,
			rootUID, rootGID, budget,
		); err != nil {
			return err
		}
	}
	return source.revalidate()
}

func createChildRootDirectory(
	parent *stableDirectory,
	name string,
	uid uint32,
	gid uint32,
	mode os.FileMode,
) error {
	if parent == nil || parent.file == nil ||
		!fixedBaseName(name) ||
		parent.revalidate() != nil {
		return ErrGuestStaging
	}
	if err := unix.Mkdirat(
		int(parent.file.Fd()), name, uint32(mode.Perm()),
	); err != nil {
		return ErrGuestStaging
	}
	path := filepath.Join(parent.path, name)
	if os.Chown(path, int(uid), int(gid)) != nil ||
		os.Chmod(path, mode.Perm()) != nil ||
		parent.file.Sync() != nil {
		return ErrGuestStaging
	}
	info, err := os.Lstat(path)
	if err != nil || !safeDirectoryInfo(info, uid, gid, mode) {
		return ErrGuestStaging
	}
	return parent.revalidate()
}

func copyAppRegularFile(
	source *stableDirectory,
	destination *stableDirectory,
	name string,
	rootUID uint32,
	rootGID uint32,
	budget *appCopyBudget,
) error {
	if source == nil || destination == nil || budget == nil ||
		source.revalidate() != nil ||
		destination.revalidate() != nil {
		return ErrGuestStaging
	}
	fd, err := unix.Openat(
		int(source.file.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return ErrGuestStaging
	}
	input := os.NewFile(uintptr(fd), name)
	if input == nil {
		_ = unix.Close(fd)
		return ErrGuestStaging
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil ||
		!before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0o022 != 0 ||
		before.Mode().Perm()&0o600 != 0o600 ||
		before.Size() <= 0 ||
		before.Size() > maximumAppFileSize {
		return ErrGuestStaging
	}
	beforeID, err := identityFromInfo(before)
	if err != nil ||
		beforeID.UID != source.uid ||
		beforeID.GID != source.gid ||
		beforeID.Links != 1 {
		return ErrGuestStaging
	}
	mode := os.FileMode(0o644)
	if before.Mode().Perm()&0o111 != 0 {
		mode = 0o755
	}
	outputFD, err := unix.Openat(
		int(destination.file.Fd()),
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		uint32(mode.Perm()),
	)
	if err != nil {
		return ErrGuestStaging
	}
	output := os.NewFile(uintptr(outputFD), name)
	if output == nil {
		_ = unix.Close(outputFD)
		return ErrGuestStaging
	}
	failed := true
	defer func() {
		if failed {
			_ = output.Close()
		}
	}()
	if output.Chown(int(rootUID), int(rootGID)) != nil ||
		output.Chmod(mode.Perm()) != nil {
		return ErrGuestStaging
	}
	written, err := io.Copy(
		output,
		io.LimitReader(input, maximumAppFileSize+1),
	)
	if err != nil || written != before.Size() ||
		written > maximumAppFileSize ||
		output.Sync() != nil {
		return ErrGuestStaging
	}
	outputInfo, err := output.Stat()
	if err != nil ||
		!safeRegularInfo(outputInfo, rootUID, rootGID, mode) ||
		outputInfo.Size() != written {
		return ErrGuestStaging
	}
	if output.Close() != nil {
		return ErrGuestStaging
	}
	failed = false
	after, afterErr := input.Stat()
	pathInfo, pathErr := os.Lstat(filepath.Join(source.path, name))
	afterID, afterIdentityErr := identityFromInfo(after)
	pathID, pathIdentityErr := identityFromInfo(pathInfo)
	if afterErr != nil || pathErr != nil ||
		afterIdentityErr != nil || pathIdentityErr != nil ||
		beforeID != afterID || afterID != pathID ||
		!os.SameFile(before, after) ||
		!os.SameFile(after, pathInfo) ||
		source.revalidate() != nil ||
		destination.revalidate() != nil ||
		destination.file.Sync() != nil {
		return ErrGuestStaging
	}
	budget.bytes += written
	if budget.bytes > maximumAppTreeSize {
		return ErrGuestStaging
	}
	return nil
}
