package vmexternalpeerlab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalAppTreeRejectsTamperExtraAndSymlink(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		root, manifest, manifestSHA, treeSHA := canonicalTreeFixture(t)
		if err := VerifyCanonicalAppTree(
			root,
			manifest,
			manifestSHA,
			treeSHA,
			uint32(os.Getuid()),
			uint32(os.Getgid()),
		); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tampered-resource", func(t *testing.T) {
		root, manifest, manifestSHA, treeSHA := canonicalTreeFixture(t)
		path := filepath.Join(root, "Contents", "Resources", "icon.icns")
		if err := os.WriteFile(path, []byte("evil"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := VerifyCanonicalAppTree(
			root, manifest, manifestSHA, treeSHA,
			uint32(os.Getuid()), uint32(os.Getgid()),
		); err == nil {
			t.Fatal("accepted a byte-changed App resource")
		}
	})
	t.Run("extra-file", func(t *testing.T) {
		root, manifest, manifestSHA, treeSHA := canonicalTreeFixture(t)
		if err := os.WriteFile(
			filepath.Join(root, "Contents", "extra"),
			[]byte("extra"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
		if err := VerifyCanonicalAppTree(
			root, manifest, manifestSHA, treeSHA,
			uint32(os.Getuid()), uint32(os.Getgid()),
		); err == nil {
			t.Fatal("accepted an unmanifested App file")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root, manifest, manifestSHA, treeSHA := canonicalTreeFixture(t)
		path := filepath.Join(root, "Contents", "Resources", "icon.icns")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/dev/null", path); err != nil {
			t.Fatal(err)
		}
		if err := VerifyCanonicalAppTree(
			root, manifest, manifestSHA, treeSHA,
			uint32(os.Getuid()), uint32(os.Getgid()),
		); err == nil {
			t.Fatal("accepted a symlinked App resource")
		}
	})
	t.Run("hard-link", func(t *testing.T) {
		root, manifest, manifestSHA, treeSHA := canonicalTreeFixture(t)
		source := filepath.Join(root, "Contents", "Resources", "icon.icns")
		if err := os.Link(
			source,
			filepath.Join(root, "Contents", "Resources", "icon-copy.icns"),
		); err != nil {
			t.Fatal(err)
		}
		if err := VerifyCanonicalAppTree(
			root, manifest, manifestSHA, treeSHA,
			uint32(os.Getuid()), uint32(os.Getgid()),
		); err == nil {
			t.Fatal("accepted a hard-linked App resource")
		}
	})
}

func canonicalTreeFixture(
	t *testing.T,
) (string, []byte, string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "KyClash.app")
	for _, path := range []string{
		root,
		filepath.Join(root, "Contents"),
		filepath.Join(root, "Contents", "MacOS"),
		filepath.Join(root, "Contents", "Resources"),
	} {
		if err := os.Mkdir(path, 0o755); err != nil ||
			os.Chmod(path, 0o755) != nil {
			t.Fatal("could not create canonical App fixture")
		}
	}
	if err := os.WriteFile(
		filepath.Join(root, "Contents", "Info.plist"),
		[]byte("<plist></plist>\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	executable := make([]byte, 64)
	copy(executable, []byte("thin-arm64-fixture"))
	if err := os.WriteFile(
		filepath.Join(root, "Contents", "MacOS", "clash-verge"),
		executable,
		0o755,
	); err != nil ||
		os.Chmod(
			filepath.Join(root, "Contents", "MacOS", "clash-verge"),
			0o755,
		) != nil {
		t.Fatal("could not create executable fixture")
	}
	if err := os.WriteFile(
		filepath.Join(root, "Contents", "Resources", "icon.icns"),
		[]byte("icon"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = resolved
	directory, err := openCanonicalTreeRoot(
		root,
		uint32(os.Getuid()),
		uint32(os.Getgid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := collectCanonicalAppTree(directory)
	closeErr := directory.close()
	if err != nil || closeErr != nil {
		t.Fatal(ErrInvalidAppManifest)
	}
	entriesBytes, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	var main canonicalAppTreeEntry
	for _, entry := range entries {
		if entry.RelativePath == "Contents/MacOS/clash-verge" {
			main = entry
			break
		}
	}
	if main.SHA256 == nil {
		t.Fatal("fixture main executable is absent")
	}
	manifest := canonicalAppTreeManifest{
		SchemaVersion: 1,
		AppName:       "KyClash.app",
		Source: canonicalAppBuildSource{
			Commit:       strings.Repeat("a", 40),
			Dirty:        true,
			StatusSHA256: strings.Repeat("b", 64),
			TreeSHA256:   strings.Repeat("c", 64),
			FileCount:    len(entries),
		},
		TreeSHA256: hashCanonicalBytes(entriesBytes),
		InfoPlist: canonicalAppInfoPlist{
			RelativePath:     "Contents/Info.plist",
			BundleIdentifier: "net.kysion.kyclash",
			ShortVersion:     "2.5.3",
			BundleVersion:    "2.5.3",
			BundleExecutable: "clash-verge",
		},
		MainExecutable: canonicalAppExecutable{
			RelativePath: main.RelativePath,
			Mode:         main.Mode,
			ByteLength:   main.ByteLength,
			SHA256:       *main.SHA256,
		},
		Entries: entries,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes = append(manifestBytes, '\n')
	return root, manifestBytes, hashCanonicalBytes(manifestBytes),
		manifest.TreeSHA256
}
