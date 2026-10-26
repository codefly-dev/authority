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
type FileReplayStore struct{ directory string }

func NewFileReplayStore(directory string) (*FileReplayStore, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("hop: replay directory must be an absolute delivered shared volume path")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return nil, errors.New("hop: delivered replay directory is unavailable")
	}
	return &FileReplayStore{directory: directory}, nil
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
