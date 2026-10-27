package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"google.golang.org/grpc/codes"
)

// organizationIsolation: an administrator acts on no organization but their
// session's, and an installation the request's organization does not hold
// answers alike whether another organization holds it or nobody does, so no
// caller learns which installations exist. A module nobody composed is
// NotFound by name wherever it is named.
func (c *client) organizationIsolation(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("every installation call stays inside the caller's organization, and an absent installation answers as a foreign one", func(t *testing.T) {
		if f.InstalledSolution == "" {
			t.Fatal("required conformance fixture missing: an active installation")
		}
		admin := as(ctx, c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken}))
		const foreign, absent = "conformance-another-org", "conformance-absent-installation"
		person := str(c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken}), "person_id")
		for _, tc := range []struct {
			name, method string
			fields       map[string]any
			reason       string
		}{
			{"review at another organization", "Review", map[string]any{"organization_id": foreign, "target": f.InstalledAudience}, "organization"},
			{"install at another organization", "Install", map[string]any{"organization_id": foreign, "target": f.InstalledAudience, "role": "viewer"}, "organization"},
			{"list another organization", "List", map[string]any{"organization_id": foreign}, "organization"},
			{"grants at another organization", "ListRoleGrants", map[string]any{"organization_id": foreign, "installation_id": f.InstalledSolution}, "organization"},
			{"grant at another organization", "GrantRole", map[string]any{"organization_id": foreign, "installation_id": f.InstalledSolution, "role": "viewer", "person_id": person}, "organization"},
			{"revoke at another organization", "RevokeRole", map[string]any{"organization_id": foreign, "installation_id": f.InstalledSolution, "role": "viewer", "person_id": person}, "organization"},
			{"grants of an absent installation", "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": absent}, "another organization"},
			{"grant on an absent installation", "GrantRole", map[string]any{"organization_id": f.Organization, "installation_id": absent, "role": "viewer", "person_id": person}, "another organization"},
			{"revoke on an absent installation", "RevokeRole", map[string]any{"organization_id": f.Organization, "installation_id": absent, "role": "viewer", "person_id": person}, "another organization"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := c.call(admin, "host.installation.v1.InstallationService", tc.method, tc.fields)
				refused(t, err, codes.PermissionDenied, tc.reason)
			})
		}
		t.Run("a module nobody composed is named as such", func(t *testing.T) {
			viewer := as(ctx, c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken}))
			_, err := c.call(viewer, "host.authority.v1.AuthorityService", "Delegate", map[string]any{"module": "conformance-not-composed", "purpose": "a job",
				"scopes": []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read"}}}})
			refused(t, err, codes.NotFound, "conformance-not-composed")
			_, err = c.call(admin, "host.installation.v1.InstallationService", "Review", map[string]any{"organization_id": f.Organization, "target": "conformance-not-composed"})
			refused(t, err, codes.NotFound, "conformance-not-composed")
		})
		t.Run("another organization's delegation is never read or ended", func(t *testing.T) {
			if f.Delegation == nil || f.OtherAdminToken == "" {
				t.Fatal("required conformance fixture missing: a delegation and another organization's administrator")
			}
			grantor := as(ctx, c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.Delegation.Token}))
			d := c.must(t, grantor, "host.authority.v1.AuthorityService", "Delegate", map[string]any{"module": f.Delegation.Module, "purpose": "isolation",
				"scopes": []any{map[string]any{"resource_kind": f.Delegation.Kind, "actions": []any{f.Delegation.Action}}}})
			other := as(ctx, c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.OtherAdminToken}))
			for _, method := range []string{"GetDelegation", "RevokeDelegation"} {
				_, err := c.call(other, "host.authority.v1.AuthorityService", method, map[string]any{"delegation_id": str(d, "delegation_id")})
				refused(t, err, codes.NotFound, "delegation")
			}
			c.must(t, grantor, "host.authority.v1.AuthorityService", "RevokeDelegation", map[string]any{"delegation_id": str(d, "delegation_id")})
		})
	})
}

// admissionKeys: only the hop registers the key it signs call admissions with;
// Keys publishes it among the admission keys with the hop-admission purpose,
// never among the Work Context keys; registering it again renews the one
// entry; any other workload, and a key that is not an Ed25519 public key, is
// refused by name.
func (c *client) admissionKeys(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("only the hop registers an admission key, published apart from the Work Context keys", func(t *testing.T) {
		if f.HopCredential == "" {
			t.Fatal("required conformance fixture missing: the hop's workload credential")
		}
		seed := sha256.Sum256([]byte("conformance hop admission"))
		public := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		register := func(credential string, key []byte) (string, error) {
			out, err := c.call(ctx, "host.authority.v1.AuthorityService", "RegisterAdmissionKey", map[string]any{
				"actor": map[string]any{"credential": credential}, "public_key": key})
			if err != nil {
				return "", err
			}
			key0 := msg(out, "key")
			if str(key0, "purpose") != stamp.Purpose {
				t.Fatalf("a registered key's purpose is %q, want %q", str(key0, "purpose"), stamp.Purpose)
			}
			return str(key0, "key_id"), nil
		}
		id, err := register(f.HopCredential, public)
		if err != nil {
			t.Fatal(err)
		}
		if id != stamp.KeyID(public) {
			t.Fatalf("the registered key id is %q, want stamp.KeyID %q", id, stamp.KeyID(public))
		}
		again, err := register(f.HopCredential, public)
		if err != nil || again != id {
			t.Fatalf("registering the key again renews it: %q %v", again, err)
		}
		keys := c.must(t, ctx, "host.authority.v1.AuthorityService", "Keys", map[string]any{})
		published := 0
		for _, k := range listMsgs(keys, "admission_keys") {
			if str(k, "key_id") == id {
				published++
				if str(k, "purpose") != stamp.Purpose || string(field(k, "public_key").Bytes()) != string(public) {
					t.Fatalf("published admission key %v", k)
				}
			}
		}
		if published != 1 {
			t.Fatalf("the hop's key is published %d times among the admission keys, want once", published)
		}
		for _, k := range listMsgs(keys, "keys") {
			if str(k, "key_id") == id || str(k, "purpose") != "work-context" {
				t.Fatalf("an admission key is never a Work Context key: %v", k)
			}
		}
		_, err = register(f.WorkloadCredential, public)
		refused(t, err, codes.PermissionDenied, "hop")
		_, err = register(f.HopCredential, public[:16])
		refused(t, err, codes.InvalidArgument, "32")
	})
}
