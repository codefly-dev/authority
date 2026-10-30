package state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/core/solutionhost"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// DeliverInstallation performs the local host's bounded synchronous callback.
// It uses only the currently admitted signed delivery. Retries are explicit
// repeats of Install with the same reviewed operation; this is not a job queue.
func (s *State) DeliverInstallation(ctx context.Context, inst Installation, transport workcontext.TransportSource) error {
	attempt, err := s.svc.PendingInstallationStep(ctx, inst)
	if err != nil {
		return err
	}
	s.mu.RLock()
	var manifest *solutionhost.ModuleManifest
	for _, record := range s.deliveries {
		m, e := record.carrier.Manifest()
		if e != nil {
			s.mu.RUnlock()
			return e
		}
		if m.Alias == inst.Target && !m.Removed {
			manifest = m
			break
		}
	}
	s.mu.RUnlock()
	if manifest == nil || manifest.Generation != attempt.Generation {
		return fmt.Errorf("installation requires its current signed delivery")
	}
	var address string
	entries := 0
	for _, endpoint := range manifest.Endpoints {
		switch strings.ToLower(endpoint.API) {
		case "http", "https", "rest", "connect":
			entries++
			if entries != 1 {
				return fmt.Errorf("installation requires one unambiguous HTTP entry endpoint")
			}
			address = endpoint.Address
		}
	}
	if address == "" {
		return fmt.Errorf("installation has no HTTP entry endpoint")
	}
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	endpoint, err := workcontext.AdmitEndpoint(address, transport, "installation callback")
	if err != nil {
		return err
	}
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "/_codefly/installations", "", "", ""
	ctx, cancel := context.WithTimeout(ctx, authority.MaxInstallationStepTTL)
	defer cancel()
	issued, err := s.svc.IssueInstallationStep(ctx, attempt, authority.MaxInstallationStepTTL)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		ID           string `json:"installation_id"`
		Organization string `json:"organization_id"`
		Revision     uint64 `json:"revision"`
	}{inst.ID, inst.Organization, inst.Revision})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(workcontext.HeaderName, issued.Token)
	req.Header.Set(workcontext.InstallationIDHeaderName, inst.ID)
	req.Header.Set(workcontext.InstallationRevisionHeaderName, strconv.FormatUint(inst.Revision, 10))
	client := &http.Client{Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("installation callback: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("installation callback returned HTTP %d", response.StatusCode)
	}
	return nil
}
