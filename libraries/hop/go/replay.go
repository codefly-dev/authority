package hop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	core "github.com/codefly-dev/core/workcontext"
)

// FileReplayStore implements Core's ReplayStore on a durable shared filesystem.
// All replicas of an audience must mount the SAME directory, isolated from
// other workloads, with atomic exclusive creation and
// durable fsync semantics. A local ephemeral volume is not a shared store.
// Reservations deliberately survive expiry and restart. Operators may remove
// files only after their recorded expiry, with all verifiers' clocks past it.
// An incomplete file is retained: an interrupted reservation fails closed.
type FileReplayStore struct {
	directory string
	shared    bool
}

// NewFileReplayStore opens a store on directory. Nothing here can tell whether
// that directory is genuinely shared by every replica: an absolute path to
// per-pod storage (/tmp, an emptyDir) looks exactly the same, and a store that
// is per-pod lets a captured admission replay once per replica. So this store
// does not declare itself shared, and NewVerifier refuses it outside a local
// run. An operator who knows the mount is shared says so with
// NewSharedFileReplayStore.
func NewFileReplayStore(directory string) (*FileReplayStore, error) {
	return openFileReplayStore(directory, false)
}

// NewSharedFileReplayStore is NewFileReplayStore for a directory the caller
// states is one durable mount every replica of this audience shares, with
// atomic exclusive creation and durable fsync semantics. Saying so is an
// assertion about the deployment that this library cannot check; a module with
// a store should prefer replaypg, where the guarantee is the database's.
func NewSharedFileReplayStore(directory string) (*FileReplayStore, error) {
	return openFileReplayStore(directory, true)
}

// Shared reports what the constructor was told. NewVerifier reads it.
func (s *FileReplayStore) Shared() bool { return s.shared }

func openFileReplayStore(directory string, shared bool) (*FileReplayStore, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("hop: replay directory must be an absolute delivered shared volume path")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return nil, errors.New("hop: delivered replay directory is unavailable")
	}
	return &FileReplayStore{directory: directory, shared: shared}, nil
}

func (s *FileReplayStore) Consume(ctx context.Context, nonce string, retainUntil time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(nonce))
	file, err := os.OpenFile(filepath.Join(s.directory, hex.EncodeToString(sum[:])), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return core.ErrReplayed
	}
	if err != nil {
		return errors.New("hop: replay store reservation unavailable")
	}
	// Never remove a reservation on error: another process may already have
	// observed it, and a failed fsync cannot safely establish whether it persisted.
	_, writeErr := fmt.Fprintf(file, "%d\n", retainUntil.Unix())
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("hop: replay reservation could not be persisted")
	}
	directory, err := os.Open(s.directory)
	if err != nil {
		return errors.New("hop: replay directory unavailable")
	}
	syncErr = directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("hop: replay directory could not be persisted")
	}
	return nil
}
