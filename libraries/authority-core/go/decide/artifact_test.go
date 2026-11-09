package decide_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The artifact decision every host makes: one policy is one kind, its action
// held on the whole kind by the parent, at the asking module's own active
// installation in the parent's organization, sourced from its namespace.
func TestOneArtifactDecisionForEveryHost(t *testing.T) {
	module := domain.Module{Name: "agent", Principal: "agent", ResourceKinds: []*basev0.WorkScopeV1{sc("agent.intents", "activate", "run")}}
	inst := domain.Installation{ID: "i-1", Organization: "acme", Target: "agent", Status: domain.Active}
	present := decide.ArtifactCaller{Module: module, Audience: "agent", Tenant: "acme", OwnerKind: "human", Held: []*basev0.WorkScopeV1{sc("agent.intents", "activate", "run")}}
	identity := func() *decide.ArtifactIdentity {
		return &decide.ArtifactIdentity{Schema: "s/v1", Source: "acme.agent", Subject: []byte("x")}
	}
	if err := decide.Artifact(present, inst, true, "i-1", "agent.intents", decide.ArtifactActivate, identity()); err != nil {
		t.Fatalf("a person present approves: %v", err)
	}
	delegated := present
	delegated.Delegated = true
	if err := decide.Artifact(delegated, inst, true, "i-1", "agent.intents", decide.ArtifactRun, identity()); err != nil {
		t.Fatalf("a delegated parent runs: %v", err)
	}
	if err := decide.Artifact(present, inst, true, "i-1", "agent.intents", decide.ArtifactActivate, nil); err != nil {
		t.Fatalf("a person present revokes: %v", err)
	}
	with := func(edit func(c *decide.ArtifactCaller, i *domain.Installation, found *bool, id *decide.ArtifactIdentity) (policy, action string)) error {
		c, i, found, id := present, inst, true, identity()
		policy, action := edit(&c, &i, &found, id)
		return decide.Artifact(c, i, found, "i-1", policy, action, id)
	}
	for name, tc := range map[string]struct {
		edit   func(c *decide.ArtifactCaller, i *domain.Installation, found *bool, id *decide.ArtifactIdentity) (string, string)
		code   domain.Code
		reason string
	}{
		"no policy": {func(*decide.ArtifactCaller, *domain.Installation, *bool, *decide.ArtifactIdentity) (string, string) {
			return "", decide.ArtifactActivate
		}, domain.Invalid, "names its policy"},
		"no subject": {func(_ *decide.ArtifactCaller, _ *domain.Installation, _ *bool, id *decide.ArtifactIdentity) (string, string) {
			id.Subject = nil
			return "agent.intents", decide.ArtifactActivate
		}, domain.Invalid, "schema, source and subject"},
		"another module's parent": {func(c *decide.ArtifactCaller, _ *domain.Installation, _ *bool, _ *decide.ArtifactIdentity) (string, string) {
			c.Audience = "other"
			return "agent.intents", decide.ArtifactActivate
		}, domain.Denied, "addressed to other"},
		"consent through a module": {func(c *decide.ArtifactCaller, _ *domain.Installation, _ *bool, _ *decide.ArtifactIdentity) (string, string) {
			c.Delegated = true
			return "agent.intents", decide.ArtifactActivate
		}, domain.Denied, "person present"},
		"an installation that does not exist": {func(_ *decide.ArtifactCaller, _ *domain.Installation, found *bool, _ *decide.ArtifactIdentity) (string, string) {
			*found = false
			return "agent.intents", decide.ArtifactRun
		}, domain.Denied, "another organization"},
		"another organization's installation": {func(_ *decide.ArtifactCaller, i *domain.Installation, _ *bool, _ *decide.ArtifactIdentity) (string, string) {
			i.Organization = "globex"
			return "agent.intents", decide.ArtifactRun
		}, domain.Denied, "another organization"},
		"another module's installation": {func(_ *decide.ArtifactCaller, i *domain.Installation, _ *bool, id *decide.ArtifactIdentity) (string, string) {
			i.Target, id.Source = "store", "acme.store"
			return "agent.intents", decide.ArtifactRun
		}, domain.Denied, "not agent's active installation"},
		"a revoked installation": {func(_ *decide.ArtifactCaller, i *domain.Installation, _ *bool, _ *decide.ArtifactIdentity) (string, string) {
			i.Status = domain.Revoked
			return "agent.intents", decide.ArtifactRun
		}, domain.Denied, "not agent's active installation"},
		"a kind the module does not serve": {func(*decide.ArtifactCaller, *domain.Installation, *bool, *decide.ArtifactIdentity) (string, string) {
			return "agent.other", decide.ArtifactRun
		}, domain.Denied, "not an artifact policy of agent"},
		"run without the run action": {func(c *decide.ArtifactCaller, _ *domain.Installation, _ *bool, _ *decide.ArtifactIdentity) (string, string) {
			c.Held = []*basev0.WorkScopeV1{sc("agent.intents", "activate")}
			return "agent.intents", decide.ArtifactRun
		}, domain.Denied, "agent.intents:run"},
		"activate held on some ids only": {func(c *decide.ArtifactCaller, _ *domain.Installation, _ *bool, _ *decide.ArtifactIdentity) (string, string) {
			c.Held = []*basev0.WorkScopeV1{{ResourceKind: "agent.intents", Actions: []string{"activate"}, ResourceIds: []string{"i-1"}}}
			return "agent.intents", decide.ArtifactActivate
		}, domain.Denied, "on the whole kind"},
		"a source other than the namespace": {func(_ *decide.ArtifactCaller, _ *domain.Installation, _ *bool, id *decide.ArtifactIdentity) (string, string) {
			id.Source = "agent"
			return "agent.intents", decide.ArtifactActivate
		}, domain.Denied, `namespace "acme.agent"`},
	} {
		t.Run(name, func(t *testing.T) {
			err := with(tc.edit)
			if code, ok := domain.CodeOf(err); !ok || code != tc.code || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want code %v naming %q; got %v", tc.code, tc.reason, err)
			}
		})
	}
}

func TestTheDigestCoversTheWholeIdentity(t *testing.T) {
	base := decide.ArtifactIdentity{Schema: "s", Source: "o", Subject: []byte("x"), ExpectedRevision: 1}
	seen := map[string]bool{decide.ArtifactDigest(base): true}
	for _, id := range []decide.ArtifactIdentity{
		{Schema: "s", Source: "o", Subject: []byte("x"), ExpectedRevision: 2},
		{Schema: "s", Source: "o", Subject: []byte("y"), ExpectedRevision: 1},
		{Schema: "s", Source: "p", Subject: []byte("x"), ExpectedRevision: 1},
		{Schema: "s", Source: "o", Subject: []byte("x"), ExpectedRevision: 1, Contracts: []decide.ArtifactContract{{Kind: "k"}}},
	} {
		d := decide.ArtifactDigest(id)
		if seen[d] || !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
			t.Fatalf("%+v: digest %s", id, d)
		}
		seen[d] = true
	}
}

// Consent in person admits one actor between the person and the asking
// module: the page hop of the page's own target, the person present on that
// page. A module's hop, or a page hop with any hop after it, is refused.
func TestConsentInPersonAdmitsThePagePresentPersonAlone(t *testing.T) {
	module := domain.Module{Name: "agent", Principal: "agent", ResourceKinds: []*basev0.WorkScopeV1{sc("agent.intents", "activate", "run")}}
	inst := domain.Installation{ID: "i-1", Organization: "acme", Target: "agent", Status: domain.Active}
	identity := &decide.ArtifactIdentity{Schema: "s/v1", Source: "acme.agent", Subject: []byte("x")}
	caller := func(chain ...*basev0.WorkActorV1) decide.ArtifactCaller {
		return decide.ArtifactCaller{Module: module, Audience: "agent", Tenant: "acme", OwnerKind: "human", Held: []*basev0.WorkScopeV1{sc("agent.intents", "activate", "run")},
			Delegated: len(chain) > 0, PagePresent: decide.PresentThroughPage(chain)}
	}
	page := &basev0.WorkActorV1{PrincipalId: "builder", PrincipalKind: decide.PageActor}
	service := &basev0.WorkActorV1{PrincipalId: "builder", PrincipalKind: "service"}
	if err := decide.Artifact(caller(page), inst, true, "i-1", "agent.intents", decide.ArtifactActivate, identity); err != nil {
		t.Fatalf("the person present on a page consents: %v", err)
	}
	for name, chain := range map[string][]*basev0.WorkActorV1{
		"a module acting":              {service},
		"a page hop, then a module":    {page, {PrincipalId: "agent-worker", PrincipalKind: "service"}},
		"a module, then a page's kind": {service, page},
	} {
		if err := decide.Artifact(caller(chain...), inst, true, "i-1", "agent.intents", decide.ArtifactActivate, identity); err == nil || !strings.Contains(err.Error(), "person present") {
			t.Fatalf("%s: want the person-present refusal, got %v", name, err)
		}
	}
}

// An owned parent's artifact is its owner's: the action owned by that owner,
// the source its installation's namespace; scopes held for two owners name no
// one artifact owner.
func TestAnOwnedParentsArtifactIsItsOwners(t *testing.T) {
	module := domain.Module{Name: "agent", Principal: "agent", ResourceKinds: []*basev0.WorkScopeV1{sc("agent.intents", "activate", "run")}}
	inst := domain.Installation{ID: "i-1", Organization: "acme", Target: "agent", Status: domain.Active}
	held := []*basev0.WorkScopeV1{{ResourceKind: "agent.intents", Actions: []string{"activate", "run"}, ResourceOwnerId: "builder-principal"}}
	owner, err := decide.ArtifactOwner(held, "agent.intents")
	if err != nil || owner != "builder-principal" {
		t.Fatalf("owner %q %v", owner, err)
	}
	caller := decide.ArtifactCaller{Module: module, Audience: "agent", Tenant: "acme", OwnerKind: "human", Held: held, Owner: owner, OwnerNamespace: "acme.builder"}
	id := func(source string) *decide.ArtifactIdentity {
		return &decide.ArtifactIdentity{Schema: "s/v1", Source: source, Subject: []byte("x")}
	}
	if err := decide.Artifact(caller, inst, true, "i-1", "agent.intents", decide.ArtifactActivate, id("acme.builder")); err != nil {
		t.Fatalf("the owner's artifact in its namespace: %v", err)
	}
	for _, source := range []string{"acme.agent", "acme.other"} {
		if err := decide.Artifact(caller, inst, true, "i-1", "agent.intents", decide.ArtifactActivate, id(source)); err == nil || !strings.Contains(err.Error(), "namespace") {
			t.Fatalf("%s: %v", source, err)
		}
	}
	unowned := caller
	unowned.Owner, unowned.OwnerNamespace = "", ""
	if err := decide.Artifact(unowned, inst, true, "i-1", "agent.intents", decide.ArtifactActivate, id("acme.agent")); err == nil {
		t.Fatal("scopes owned by the builder do not hold the module installation's own artifact")
	}
	noNamespace := caller
	noNamespace.OwnerNamespace = ""
	if err := decide.Artifact(noNamespace, inst, true, "i-1", "agent.intents", decide.ArtifactRun, id("acme.builder")); err == nil {
		t.Fatal("an owner with no installation here has no namespace")
	}
	if _, err := decide.ArtifactOwner(append(held, sc("agent.intents", "run")), "agent.intents"); err == nil {
		t.Fatal("owned beside unowned names no one owner")
	}
}
