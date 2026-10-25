package state_test

import (
	"context"
	"errors"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	"github.com/codefly-dev/core/workcontext"
)

func TestInstallationAgentSealIsBoundedToLiveSameOrganizationModules(t *testing.T) {
	for _, tc := range []struct {
		name, source, org, target string
		revoke                    string
		allowed                   bool
	}{
		{name: "same organization module", source: "wiki", org: "acme", target: "documents", allowed: true},
		{name: "own installation", source: "wiki", org: "acme", target: "wiki", allowed: true},
		{name: "foreign organization", source: "wiki", org: "globex", target: "documents"},
		{name: "unknown agent", source: "missing", org: "acme", target: "documents"},
		{name: "module is not a solution agent", source: "org-directory", org: "acme", target: "documents"},
		{name: "revoked source", source: "wiki", org: "acme", target: "documents", revoke: "wiki"},
		{name: "pending source", source: "wiki", org: "acme", target: "documents", revoke: "wiki"},
		{name: "revoked module", source: "wiki", org: "acme", target: "documents", revoke: "documents"},
		{name: "another solution", source: "wiki", org: "acme", target: "proposals"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := testkit.New(t)
			if tc.target == "proposals" {
				if _, err := k.State.ApplyManifest(testkit.Proposals(1)); err != nil {
					t.Fatal(err)
				}
				if _, err := k.State.Install(context.Background(), "acme", "proposals", "viewer", "alex"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.revoke != "" {
				if err := k.State.Revoke(state.InstallationID("acme", tc.revoke)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "pending source" {
				k.State.OnInstall(func(context.Context, state.Installation) error { return errors.New("not ready") })
				inst, err := k.State.Install(context.Background(), "acme", "wiki", "viewer", "alex")
				if err == nil || inst.Status != state.Pending {
					t.Fatalf("pending source precondition: %+v %v", inst, err)
				}
			}
			target := state.InstallationID(tc.org, tc.target)
			got, err := k.State.Seal(context.Background(), state.InstallationID("acme", tc.source)+"/agent", target)
			if tc.allowed {
				if err != nil || got.InstallationID != target || got.InstallationRevision == 0 {
					t.Fatalf("active installation association: %+v %v", got, err)
				}
			} else if !errors.Is(err, workcontext.ErrNoSeal) {
				t.Fatalf("unrelated installation association: %+v %v", got, err)
			}
		})
	}
}
