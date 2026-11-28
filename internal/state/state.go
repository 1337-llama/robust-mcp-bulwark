// Package state manages the state directory and server identity (DESIGN.md
// §5.3, §9; spec 002 AC-29, AC-30).
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/1337-llama/robust-mcp-bulwark/internal/canon"
	"github.com/1337-llama/robust-mcp-bulwark/internal/jsonrpc"
)

// Prepare creates dir (0700) and returns a warning for every group- or
// world-writable entry in it. In enforce mode any such entry is an error (T-08).
func Prepare(dir, mode string) (warnings []string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil { // inspect what the link points to
		return nil, err
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o022 != 0 {
			warnings = append(warnings, fmt.Sprintf("%s is group- or world-writable (%v)", p, info.Mode().Perm()))
		}
		return nil
	})
	if err == nil && mode == "enforce" && len(warnings) > 0 {
		err = fmt.Errorf("refusing to start in enforce mode: %s", warnings[0])
	}
	return warnings, err
}

// CommandDigest is SHA-256 over the canonical form of {argv, resolved
// executable path, SHA-256 of the executable file} (DESIGN.md §5.3).
func CommandDigest(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("no command")
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return "", err
	}
	if path, err = filepath.Abs(path); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{"argv": argv, "executable": path, "executable_sha256": hex.EncodeToString(h.Sum(nil))})
	v, err := jsonrpc.ParseValue(b, 8)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon.Bytes(v))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ServerID returns the configured id or, outside enforce mode, the default
// auto-<first 12 hex digits of the command digest> (AC-30).
func ServerID(flag, mode, digest string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if mode == "enforce" {
		return "", fmt.Errorf("--server-id is required in enforce mode")
	}
	if len(digest) < len("sha256:")+12 {
		return "", fmt.Errorf("invalid command digest")
	}
	return "auto-" + digest[len("sha256:"):len("sha256:")+12], nil
}
