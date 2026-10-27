package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

const artifactService = "host.artifact.v1.ArtifactService"

// ArtifactCase is a module installed at one organization with one installed
// artifact policy (codefly.dev/artifact): a person's consent to an exact
// authored artifact the module runs, for that installation. The host composes
// and installs the module; the suite asks over the published interfaces
// alone, as the module does, with its workload credential and a parent Work
// Context a person was issued at the module.
//
// One definition, every host (the shared core's authority.DecideArtifact):
//   - a policy is a resource kind the module serves, nothing more: Policy;
//   - approving and revoking need the person present (a human owner, no
//     module between) holding Policy's activate action at the module, a run
//     its run action; the parent holds it on the whole kind, never on some
//     ids; administrator or not, the action decides;
//   - the installation is the module's own, active, at the parent's
//     organization; the artifact's source is its namespace, as
//     InstallationService.Current names it;
//   - the approval is host/approved-artifacts/<id>, its digest
//     sha256:<hex> of the identity's deterministic protobuf encoding, and
//     every answer carries the revision the approval was given at;
//   - a request missing its policy or identity is InvalidArgument; every
//     other refusal is PermissionDenied with a reason.
//
// Admin is an administrator of the organization holding Policy's activate
// and run actions at Module; Approver a member who is not an administrator
// and holds both through a role; Member a member holding run and not
// activate. OtherCredential is the workload credential of another composed
// module. OtherAdmin is an administrator of another organization, where the
// module is not installed: every installation it lists is one the module
// cannot name.
type ArtifactCase struct {
	Module, Credential, OtherCredential string
	Policy                              string
	Admin, Approver, Member, OtherAdmin string
}

// RunArtifacts proves a host decides artifact consent as every host does.
func RunArtifacts(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f ArtifactCase) {
	t.Helper()
	c, err := newClient(conn, descriptors)
	if err != nil {
		t.Fatalf("conformance: %v", err)
	}
	identityType, err := c.files.FindDescriptorByName("host.artifact.v1.Identity")
	if err != nil {
		t.Fatalf("required interface absent: codefly.dev/artifact (%s): %v", artifactService, err)
	}
	if f.Module == "" || f.Credential == "" || f.OtherCredential == "" || f.Policy == "" || f.Admin == "" || f.Approver == "" || f.Member == "" || f.OtherAdmin == "" {
		t.Fatal("required conformance fixture missing: artifact case")
	}
	ctx := context.Background()
	sessions := map[string]protoreflect.Message{}
	signIn := func(t *testing.T, token string) protoreflect.Message {
		t.Helper()
		if _, ok := sessions[token]; !ok {
			sessions[token] = c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": token})
		}
		return sessions[token]
	}
	// A person's parent at the module: what they hold there, or exactly the
	// policy's actions named (on the ids named, when any).
	parent := func(t *testing.T, token string, actions []string, ids ...string) string {
		t.Helper()
		ask := map[string]any{"person": map[string]any{}, "audience": f.Module}
		if actions != nil {
			ask["scopes"] = []any{scopeAsk(f.Policy, actions, ids)}
		}
		return str(c.must(t, as(ctx, signIn(t, token)), "host.authority.v1.AuthorityService", "Issue", ask), "token")
	}
	both := parent(t, f.Admin, []string{"activate", "run"})
	current := c.must(t, ctx, "host.installation.v1.InstallationService", "Current", map[string]any{"parent_token": both, "actor_credential": f.Credential})
	installation, namespace := str(current, "id"), str(current, "namespace")
	if installation == "" || namespace == "" || str(current, "target") != f.Module || str(current, "organization_id") != str(signIn(t, f.Admin), "organization_id") {
		t.Fatalf("the module's current installation: %v", current)
	}
	identity := func(subject string, revision int64) map[string]any {
		return map[string]any{"schema": "conformance.artifact/v1", "source": namespace, "subject": []byte(subject), "expected_revision": revision,
			"contracts": []any{map[string]any{"kind": "engine", "name": "conformance-engine", "digest": "sha256:" + strings.Repeat("ab", 32)}}}
	}
	// The digest every host answers: sha256 of the identity's deterministic
	// protobuf encoding.
	digestOf := func(t *testing.T, id map[string]any) string {
		t.Helper()
		m := dynamicpb.NewMessage(identityType.(protoreflect.MessageDescriptor))
		if err := fill(m, id); err != nil {
			t.Fatal(err)
		}
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	ask := func(parentToken, credential, inst, policy string, id map[string]any) map[string]any {
		return map[string]any{"parent_token": parentToken, "actor_credential": credential, "installation_id": inst, "policy": policy, "identity": id}
	}
	const revision = int64(7)
	standing := ask(both, f.Credential, installation, f.Policy, identity("conformance-intent", revision))
	call := func(method string, req map[string]any) (protoreflect.Message, error) {
		return c.call(ctx, artifactService, method, req)
	}
	same := func(t *testing.T, got, want protoreflect.Message) {
		t.Helper()
		if !proto.Equal(got.Interface(), want.Interface()) {
			t.Fatalf("answered %v, not the approval %v", got, want)
		}
	}

	approved := c.must(t, ctx, artifactService, "Approve", standing)
	t.Run("an administrator present approves the exact artifact through the module", func(t *testing.T) {
		if !strings.HasPrefix(str(approved, "qualified_name"), "host/approved-artifacts/") || str(approved, "digest") != digestOf(t, identity("conformance-intent", revision)) ||
			i64(approved, "expected_revision") != revision {
			t.Fatalf("approval = %v; want host/approved-artifacts/<id>, the identity's digest and revision %d", approved, revision)
		}
		same(t, c.must(t, ctx, artifactService, "Approve", standing), approved)
	})
	t.Run("a run reads back the same approval, at the revision it was given", func(t *testing.T) {
		same(t, c.must(t, ctx, artifactService, "Authorize", standing), approved)
		// The member holds run and not activate: a run is theirs, consent is not.
		member := parent(t, f.Member, nil)
		same(t, c.must(t, ctx, artifactService, "Authorize", ask(member, f.Credential, installation, f.Policy, identity("conformance-intent", revision))), approved)
		for name, id := range map[string]map[string]any{
			"another artifact":                      identity("another conformance-intent", revision),
			"the same artifact at another revision": identity("conformance-intent", revision+1),
		} {
			_, err := call("Authorize", ask(both, f.Credential, installation, f.Policy, id))
			if err == nil {
				t.Fatalf("%s ran unapproved", name)
			}
			refused(t, err, codes.PermissionDenied, "")
		}
	})
	t.Run("the policy's activate action is consent, administrator or not", func(t *testing.T) {
		approver := parent(t, f.Approver, nil)
		id := identity("conformance-approver-intent", revision)
		mine := c.must(t, ctx, artifactService, "Approve", ask(approver, f.Credential, installation, f.Policy, id))
		if str(mine, "digest") != digestOf(t, id) || str(mine, "qualified_name") == str(approved, "qualified_name") {
			t.Fatalf("the approver's approval = %v", mine)
		}
		same(t, c.must(t, ctx, artifactService, "Authorize", ask(both, f.Credential, installation, f.Policy, id)), mine)
	})

	member := parent(t, f.Member, nil)
	activateOnly, runOnly := parent(t, f.Admin, []string{"activate"}), parent(t, f.Admin, []string{"run"})
	someIDs := map[string]string{"activate": parent(t, f.Admin, []string{"activate"}, installation), "run": parent(t, f.Admin, []string{"run"}, installation)}
	foreign := c.foreignInstallations(t, ctx, f)
	for _, method := range []string{"Approve", "Authorize"} {
		action, without := "activate", runOnly
		if method == "Authorize" {
			action, without = "run", activateOnly
		}
		t.Run(method+" refuses who must not decide, with a reason", func(t *testing.T) {
			probes := map[string]map[string]any{
				"a policy the module does not have":                ask(both, f.Credential, installation, "conformance-no-such-policy", identity("conformance-intent", revision)),
				"no workload credential":                           ask(both, "", installation, f.Policy, identity("conformance-intent", revision)),
				"the parent presented by another module":           ask(both, f.OtherCredential, installation, f.Policy, identity("conformance-intent", revision)),
				"a parent without " + action:                       ask(without, f.Credential, installation, f.Policy, identity("conformance-intent", revision)),
				"a parent holding " + action + " on some ids only": ask(someIDs[action], f.Credential, installation, f.Policy, identity("conformance-intent", revision)),
				"an installation that does not exist":              ask(both, f.Credential, "conformance-no-such-installation", f.Policy, identity("conformance-intent", revision)),
				"a source other than the installation's namespace": ask(both, f.Credential, installation, f.Policy, mapWith(identity("conformance-intent", revision), "source", namespace+".elsewhere")),
			}
			if method == "Approve" {
				probes["a member without activate, at Approve"] = ask(member, f.Credential, installation, f.Policy, identity("conformance-intent", revision))
			}
			for name, inst := range foreign {
				probes[name] = ask(both, f.Credential, inst, f.Policy, identity("conformance-intent", revision))
			}
			for name, req := range probes {
				t.Run(name, func(t *testing.T) {
					_, err := call(method, req)
					refused(t, err, codes.PermissionDenied, "")
				})
			}
			for name, req := range map[string]map[string]any{
				"no policy":  ask(both, f.Credential, installation, "", identity("conformance-intent", revision)),
				"no subject": ask(both, f.Credential, installation, f.Policy, mapWith(identity("conformance-intent", revision), "subject", []byte(nil))),
			} {
				t.Run("malformed: "+name, func(t *testing.T) {
					_, err := call(method, req)
					refused(t, err, codes.InvalidArgument, "")
				})
			}
		})
	}

	t.Run("revocation ends the approval for good", func(t *testing.T) {
		id := strings.TrimPrefix(str(approved, "qualified_name"), "host/approved-artifacts/")
		revoke := func(parentToken, credential, inst string) map[string]any {
			return map[string]any{"parent_token": parentToken, "actor_credential": credential, "installation_id": inst, "policy": f.Policy, "approval_id": id}
		}
		probes := map[string]map[string]any{
			"a member without activate":              revoke(member, f.Credential, installation),
			"a parent without activate":              revoke(runOnly, f.Credential, installation),
			"no workload credential":                 revoke(both, "", installation),
			"the parent presented by another module": revoke(both, f.OtherCredential, installation),
		}
		for name, inst := range foreign {
			probes[name] = revoke(both, f.Credential, inst)
		}
		for name, req := range probes {
			_, err := call("Revoke", req)
			if err == nil {
				t.Fatalf("revoke by %s succeeded", name)
			}
			refused(t, err, codes.PermissionDenied, "")
		}
		same(t, c.must(t, ctx, artifactService, "Authorize", standing), approved)
		same(t, c.must(t, ctx, artifactService, "Revoke", revoke(both, f.Credential, installation)), approved)
		for _, method := range []string{"Authorize", "Approve"} {
			_, err := call(method, standing)
			refused(t, err, codes.PermissionDenied, "")
		}
	})
}

// mapWith is m with one field replaced.
func mapWith(m map[string]any, field string, value any) map[string]any {
	out := clone(m)
	out[field] = value
	return out
}

// foreignInstallations are the installations the module cannot name with a
// parent of the admin's organization, by what they are: that organization's
// installations of other targets, and every installation of OtherAdmin's
// organization, where the module is not installed.
func (c *client) foreignInstallations(t *testing.T, ctx context.Context, f ArtifactCase) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, probe := range []struct{ token, whose string }{{f.Admin, "this organization's"}, {f.OtherAdmin, "another organization's"}} {
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": probe.token})
		listed := c.must(t, as(ctx, sess), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": str(sess, "organization_id")})
		for _, inst := range listMsgs(listed, "installations") {
			mine := str(inst, "target") == f.Module
			switch {
			case probe.token == f.Admin && mine:
				continue
			case probe.token == f.OtherAdmin && mine && enumName(inst, "status") == "STATUS_ACTIVE":
				t.Fatalf("required conformance fixture: the module is installed at the other administrator's organization (%s)", str(inst, "id"))
			}
			out[fmt.Sprintf("%s installation of %s (%s)", probe.whose, str(inst, "target"), enumName(inst, "status"))] = str(inst, "id")
		}
	}
	for name := range out {
		if strings.HasPrefix(name, "another organization's") {
			return out
		}
	}
	t.Fatal("required conformance fixture missing: the other administrator's organization lists no installation to name")
	return nil
}
