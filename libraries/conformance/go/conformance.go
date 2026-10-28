// Package conformance is the suite every implementation of the host interfaces
// must pass: the local authority and the host's accounts alike. It links no
// generated Go package, because an implementation links its own and a second
// registration of the same proto file panics; it drives the interfaces from
// their published descriptors (the contract.binpb codefly generate writes) with
// dynamic messages over any gRPC connection.
package conformance

import (
	"context"
	"slices"

	"crypto/sha256"
	"encoding/hex"
	"fmt"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"github.com/codefly-dev/core/solutionhost"
	"github.com/codefly-dev/core/workcontext"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Fixture is what the suite assumes the implementation seeded.
type Fixture struct {
	// WorkloadOrganizations proves both mandatory empty-tenant isolation refusals.
	WorkloadOrganizations *WorkloadOrganizationsCase
	Organization          string // the one organisation the people belong to
	ViewerToken           string // signs in a person who may read ReadKind at Audience and nothing more
	UnentitledToken       string // signs in a member with neither roles nor teams; empty leaves this line unproven
	AdminToken            string // signs in an organisation administrator
	Audience              string // a composed module the viewer holds "read" on
	ReadKind              string // the resource kind the viewer may read at Audience
	WorkloadModule        string // the principal of the module WorkloadCredential names; a person's token for its hop is addressed here
	WorkloadCredential    string // the credential of a composed module's workload; the module declares Binding, addressed to BindingAudience
	Binding               string // the workload module's operation binding whose invoke scopes cover "read" on ReadKind
	BindingAudience       string // the audience Binding is addressed to; a hop exercising Binding is addressed here
	Elsewhere             string // a composed audience the viewer's context at Audience is not addressed to
	InstalledSolution     string // an active installation the viewer is entitled to
	InstalledCredential   string // workload credential of InstalledAudience, required for installation-owned Issue
	InstalledAudience     string // the installed solution principal; distinct from the organisation-role module Audience

	// LocalAdvisory enables the local-only advisory Check contract.
	LocalAdvisory bool

	// SolutionRoles proves a delivered solution role, independently of organization grants.
	SolutionRoles *SolutionRoleCase
	// Lifecycle controls the real install-step acknowledgement and revocation.
	Lifecycle *InstallationLifecycleCase
	// OwnerToken is a member with the organization owner role, not admin.
	OwnerToken string
	// OtherAdminToken signs in an administrator of another organization.
	OtherAdminToken string
	// HopCredential is the workload credential of the composition's hop, the
	// one workload that registers admission keys.
	HopCredential string

	// ReviewOfferNotServed is why this host does not serve
	// OfferService.ReviewOffer yet. Set, the declaration case skips comparing
	// the reviewed offer, naming the reason, and fails once the host serves it;
	// every other line of that case still runs. Empty: the host serves it.
	ReviewOfferNotServed string

	// SolutionTools exercises a module binding to a solution with distinct person entitlements.
	SolutionTools *SolutionToolsCase

	// A delivery, as Codefly signs it. The suite requires signed carriers:
	// core's module manifest for HostCoordinate and HostDomain, signed by
	// SignManifest, carried by DeliveryCredential(module).
	HostCoordinate     string
	HostDomain         string
	SignManifest       func(document []byte) (envelope []byte, err error)
	DeliveryCredential func(module string) string
	// InstallModule, for a host whose administrators install each module by
	// their own consent, installs one the suite just delivered at the
	// organizations the suite uses, through the host's own path; it must be
	// idempotent, since a module is delivered again at newer generations. nil:
	// delivery installs a module at every organization.
	InstallModule func(ctx context.Context, module string) error
	// Resources is required and states what a person covers on one kind.
	Resources *ResourceCase
	// Lookup is a binding whose lookup scopes are narrower than its invoke
	// scopes; required for complete conformance.
	Lookup *LookupCase
	// Delegation is a required grant a person makes to a module.
	Delegation *DelegationCase
	// SignAuthority signs the authority's own document delivered with a manifest,
	// with the key SignManifest signs with. Required for method-policy conformance.
	SignAuthority func(document []byte) (envelope []byte, err error)

	// Chain is a required delegate chain: a person signs in,
	// is issued at Start, and each hop is taken by its module on the previous
	// token, through its binding. The last hop asks for something the first
	// token never carried, so it holds only if each hop inherits from the owner.
	Chain *Chain
	// ChildScopes proves current effective target scopes within a stored
	// delegation's enduring ceiling. Omission fails conformance.
	ChildScopes *ChildScopesCase
	// ParentLimits proves persistent per-kind limits, including entirely dropped kinds.
	ParentLimits *ParentLimitsCase
	// InstallationResources proves role scopes a solution declares
	// installation-owned: resolved to what each installation owns, never the
	// whole kind, and never widened by a child. Omission fails conformance.
	InstallationResources *InstallationResourcesCase
	// InstallationChain exercises successive module actors under one installed
	// solution's role. Omission fails conformance.
	InstallationChain *InstallationChainCase

	// SlowChecks is retained for source compatibility. Expiry is now always
	// checked: omitting a fixture option must not silently remove a contract case.
	SlowChecks bool

	// Matrix is the permission matrix the fixture states: for each person, at
	// each audience, each kind and action is allowed or refused. The suite asks
	// for exactly that scope and expects the answer, so every role a fixture
	// declares is proven allow and deny.
	Matrix []Expectation
}

// Chain is one delegate chain: who, where it starts, and each hop.
type Chain struct {
	Token string // the person's fixture token
	Start string // the audience of the person's token, the first module acting
	Hops  []Hop
}

// Hop is one module acting on the previous token.
type Hop struct {
	Credential string // the acting module's workload credential
	Binding    string // its binding, addressed to Audience
	Audience   string
	AskKind    string // what this hop asks for at Audience
	AskAction  string
}

// ResourceCase is one ListResources expectation: a person signed in with Token
// and issued at Audience on Covered covers each id of Covered and none of
// Uncovered for Action on Kind, and does not hold Unheld on Kind at all. An
// ask naming an id of Uncovered, or the whole kind, is refused.
type ResourceCase struct {
	Token     string
	Audience  string
	Kind      string
	Action    string
	Covered   []string
	Uncovered []string
	Unheld    string
}

// LookupCase: a person (Token) issued at Start; the module there (Credential)
// hops through Binding to Audience, where invoking may Invoke on Kind and a
// lookup may only Lookup.
type LookupCase struct {
	Token, Start, Credential, Binding, Audience, Kind, Invoke, Lookup string
}

// DelegationCase: a person (Token) delegates Action on Kind to Module, whose
// workload (Credential) issues from it through Binding to Audience; Outsider
// signs in a person who does not hold Action and so cannot delegate it.
type DelegationCase struct {
	Token, Outsider, Module, Credential, Binding, Audience, Kind, Action string
}

// Expectation is one cell of the permission matrix.
type Expectation struct {
	Token    string // the person's fixture token
	Audience string
	Kind     string
	Action   string
	Allowed  bool
}

// applyManifest composes one module at one generation as a signed carrier.
// A solution declares its installer and viewer roles in the paired authority
// document, since core's manifest carries no roles.
func (c *client) applyManifest(ctx context.Context, f Fixture, alias, kind string, generation uint64, kinds []string) (protoreflect.Message, error) {
	var roles, ceilings []any
	if kind == "solution" {
		var all, reads []any
		for _, k := range kinds {
			all = append(all, map[string]any{"resource_kind": k, "actions": []any{"read", "write"}})
			reads = append(reads, map[string]any{"resource_kind": k, "actions": []any{"read"}})
		}
		roles = []any{map[string]any{"name": "installer", "scopes": all}, map[string]any{"name": "viewer", "scopes": reads}}
		ceilings = all
	}
	if roles == nil {
		return c.deliver(ctx, f, alias, kind, generation, kinds, nil, 0)
	}
	// A solution receives owner-selected scopes, so it declares owner-aware
	// checking.
	document := map[string]any{"scope_ceilings": ceilings, "roles": roles, "owner_aware": true}
	return c.deliver(ctx, f, alias, kind, generation, kinds, document, 0)
}

// deliverWithMethods delivers a signed module manifest with the authority's
// document listing methods. skew offsets the document's generation from the
// manifest's, to prove a mismatched pair is refused.
func (c *client) deliverWithMethods(ctx context.Context, f Fixture, alias string, generation uint64, kinds []string, methods []any, skew uint64) (protoreflect.Message, error) {
	return c.deliver(ctx, f, alias, "module", generation, kinds, map[string]any{"methods": methods}, skew)
}

// deliver delivers a signed manifest as the CLI does: core's manifest under the
// fixture's release key, carried by the module's own delivery credential, and,
// when document names any field, the authority's own document signed by the same
// key and bound to the manifest by module, generation and digest.
func (c *client) deliver(ctx context.Context, f Fixture, alias, kind string, generation uint64, kinds []string, document map[string]any, skew uint64, bindings ...solutionhost.AuthorityBinding) (protoreflect.Message, error) {
	if f.SignManifest == nil || f.DeliveryCredential == nil {
		return nil, fmt.Errorf("composition requires a release signer and delivery workload credential")
	}
	if document != nil && f.SignAuthority == nil {
		return nil, fmt.Errorf("composition with an authority document requires its release signer")
	}
	manifest := &solutionhost.ModuleManifest{
		Schema: solutionhost.SchemaModuleManifestV1, Binding: alias, Alias: alias, Kind: solutionhost.Kind(kind), Generation: generation,
		Host:      solutionhost.HostTarget{Coordinate: f.HostCoordinate, Domain: f.HostDomain},
		Release:   solutionhost.Release{Publisher: "conformance", Name: alias, Version: "0.1.0"},
		Workloads: []solutionhost.Workload{{Service: alias, Container: "app"}},
		Authority: &solutionhost.Authority{Principal: alias, ResourceKinds: kinds},
	}
	if len(bindings) > 0 {
		manifest.Authority.Bindings = bindings
	}
	carrier, err := solutionhost.SignedPayload(manifest)
	if err != nil {
		return nil, err
	}
	envelope, err := f.SignManifest(carrier)
	if err != nil {
		return nil, err
	}
	request := map[string]any{
		"carrier": map[string]any{"document": carrier, "envelope": envelope}, "credential": f.DeliveryCredential(alias)}
	if document == nil {
		return installed(ctx, f, alias, kind)(c.call(ctx, "host.composition.v1.CompositionService", "ApplyManifest", request))
	}
	d, err := c.files.FindDescriptorByName("host.composition.v1.AuthorityManifestV1")
	if err != nil {
		return nil, err
	}
	doc := dynamicpb.NewMessage(d.(protoreflect.MessageDescriptor))
	sum := sha256.Sum256(carrier)
	fields := map[string]any{"module": alias, "generation": generation + skew, "core_manifest_digest": "sha256:" + hex.EncodeToString(sum[:])}
	for name, value := range document {
		fields[name] = value
	}
	if err := fill(doc, fields); err != nil {
		return nil, err
	}
	authority, err := (proto.MarshalOptions{Deterministic: true}).Marshal(doc)
	if err != nil {
		return nil, err
	}
	signed, err := f.SignAuthority(authority)
	if err != nil {
		return nil, err
	}
	request["authority"] = map[string]any{"document": authority, "envelope": signed}
	return installed(ctx, f, alias, kind)(c.call(ctx, "host.composition.v1.CompositionService", "ApplyManifest", request))
}

// installed has the host install a module it just composed, when its
// administrators install modules by consent (Fixture.InstallModule).
func installed(ctx context.Context, f Fixture, alias, kind string) func(protoreflect.Message, error) (protoreflect.Message, error) {
	return func(out protoreflect.Message, err error) (protoreflect.Message, error) {
		if err != nil || kind != "module" || f.InstallModule == nil {
			return out, err
		}
		if err := f.InstallModule(ctx, alias); err != nil {
			return nil, fmt.Errorf("the host installing %s: %w", alias, err)
		}
		return out, nil
	}
}

// Run drives the suite over one connection, from the published descriptors.
func Run(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f Fixture) {
	t.Helper()
	c, err := newClient(conn, descriptors)
	if err != nil {
		t.Fatalf("conformance: %v", err)
	}
	ctx := context.Background()
	c.admissionStatus(t, ctx, f)
	c.solutionRoleCases(t, ctx, f)
	c.solutionDeclaration(t, ctx, f)
	c.installationIdentity(t, ctx, f)
	c.currentInstallation(t, ctx, f)
	c.sessionDisplayNames(t, ctx, f)
	c.bindingRefusals(t, ctx, f)
	c.forwardedContext(t, ctx, f)
	t.Run("parent per-kind limits survive audience changes", func(t *testing.T) {
		if f.ParentLimits == nil {
			t.Fatal("fixture supplies no parent-limit round trip")
		}
		c.parentLimits(t, ctx, *f.ParentLimits)
	})

	t.Run("keys name one Ed25519 key and an issuer", func(t *testing.T) {
		keys := c.must(t, ctx, "host.authority.v1.AuthorityService", "Keys", map[string]any{})
		if str(keys, "issuer") == "" || count(keys, "keys") == 0 || str(listMsgs(keys, "keys")[0], "algorithm") != "Ed25519" {
			t.Fatalf("keys: %v", keys)
		}
	})
	t.Run("a fixture person signs in and an unknown token is refused", func(t *testing.T) {
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		if str(sess, "session_id") == "" || str(sess, "bearer") == "" || str(sess, "organization_id") != f.Organization {
			t.Fatalf("sign in: %v", sess)
		}
		_, err := c.call(ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": "not-a-person"})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("unknown token: %v", err)
		}
	})
	t.Run("every fixture person listed signs in as that person", func(t *testing.T) {
		// A host that signs real people in lists none, and the line holds.
		listed := c.must(t, ctx, "host.session.v1.SessionService", "ListFixturePeople", map[string]any{})
		for _, person := range listMsgs(listed, "people") {
			sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": str(person, "fixture_token")})
			if str(sess, "person_id") != str(person, "person_id") || str(sess, "organization_id") != str(person, "organization_id") || str(sess, "organization_display_name") != str(person, "organization_display_name") {
				t.Fatalf("listed %v signed in as %v", person, sess)
			}
		}
	})
	t.Run("a page asks who its bearer is, and a bearer naming no session is refused", func(t *testing.T) {
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		current := c.must(t, as(ctx, sess), "host.session.v1.SessionService", "Current", map[string]any{})
		if str(current, "session_id") != str(sess, "session_id") || str(current, "person_id") != str(sess, "person_id") || str(current, "organization_id") != f.Organization || str(current, "bearer") != "" {
			t.Fatalf("current: %v", current)
		}
		for name, caller := range map[string]context.Context{
			"no bearer":       ctx,
			"a forged bearer": metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer not-a-session"),
		} {
			if _, err := c.call(caller, "host.session.v1.SessionService", "Current", map[string]any{}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})
	t.Run("a person is issued, checked, and refused elsewhere", func(t *testing.T) {
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		asViewer := as(ctx, sess)
		read := []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read"}}}
		out := c.must(t, asViewer, "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience, "scopes": read})
		wc := msg(out, "context")
		if str(wc, "owner_principal_id") != str(sess, "person_id") || str(wc, "audience") != f.Audience || str(wc, "tenant_id") != f.Organization {
			t.Fatalf("context = %v", wc)
		}
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Audience})
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Elsewhere})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("check at another audience: %v", err)
		}
		_, err = c.call(asViewer, "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience,
			"scopes": []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read", "write", "ingest", "admin"}}}})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("beyond the role must be PermissionDenied, got %v", err)
		}
	})
	t.Run("an empty ask means everything the owner holds at the audience", func(t *testing.T) {
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		out := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience})
		if count(msg(out, "context"), "authority_scopes") == 0 {
			t.Fatalf("an empty ask was issued nothing: %v", out)
		}
	})
	t.Run("the permission matrix holds, allow and deny", func(t *testing.T) {
		if len(f.Matrix) == 0 {
			t.Fatal("required conformance fixture missing: the fixture states no matrix")
		}
		sessions := map[string]protoreflect.Message{}
		for _, e := range f.Matrix {
			sess, ok := sessions[e.Token]
			if !ok {
				sess = c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": e.Token})
				sessions[e.Token] = sess
			}
			// Under the solution-principal contract a solution audience's scopes
			// are owned by its principal: the row asks within that owner.
			ask := ownedBy(map[string]any{"resource_kind": e.Kind, "actions": []any{e.Action}}, c.heldOwner(ctx, sess, e.Audience, e.Kind))
			_, err := c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": e.Audience,
				"scopes": []any{ask}})
			switch {
			case e.Allowed && err != nil:
				t.Errorf("%s at %s: %s %s must be allowed: %v", e.Token, e.Audience, e.Kind, e.Action, err)
			case !e.Allowed && status.Code(err) != codes.PermissionDenied:
				t.Errorf("%s at %s: %s %s must be refused as PermissionDenied, got %v", e.Token, e.Audience, e.Kind, e.Action, err)
			}
		}
	})
	t.Run("a callee refuses what does not verify, by name", func(t *testing.T) {
		// The callee contract, as the hop will enforce it: a token is accepted only
		// when its signature holds, its window is open, it is addressed to this
		// audience, and the authority it was sealed to still stands. Each failure
		// is refused with a code the caller can act on, never a silent pass.
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		read := []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read"}}}
		out := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience, "scopes": read})
		token := str(out, "token")
		tampered := token[:len(token)-4] + map[bool]string{true: "AAAA", false: "BBBB"}[!strings.HasSuffix(token, "AAAA")]
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": tampered, "audience": f.Audience}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("a tampered token is Unauthenticated: %v", err)
		}
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": "not.a.token", "audience": f.Audience}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("a token that is not a token is Unauthenticated: %v", err)
		}
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": "not-composed"}); err == nil {
			t.Fatal("a check at an audience that is not composed is refused")
		}
		// A window is honoured with core's clock skew: a token is refused once it
		// is past its expiry by more than DefaultSkew (30 s). Waiting that long is
		// required; the fast check also asserts the window the token states.
		short := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience, "scopes": read, "ttl_seconds": int64(1)})
		if i64(msg(short, "context"), "expires_at_unix")-i64(msg(short, "context"), "issued_at_unix") > 1 {
			t.Fatalf("a one-second window is issued as asked: %v", msg(short, "context"))
		}
		t.Run("an expired capability is refused after clock skew", func(t *testing.T) {
			time.Sleep(workcontext.DefaultSkew + 2*time.Second)
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(short, "token"), "audience": f.Audience})
			refused(t, err, codes.Unauthenticated, "expired")
		})
		if f.InstalledSolution == "" {
			t.Fatal("required conformance fixture missing: staleness needs an installation")
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": f.Audience})
		// A grant moves only its subject's authority: the callee refuses a
		// capability once its person's roles are revoked. The fixture's grants are restored
		// exactly, and a viewer reaching the installation through a team
		// would keep access, so the fixture must not grant one.
		viewer := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		installation := map[string]any{"organization_id": f.Organization, "installation_id": f.InstalledSolution}
		held := c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "ListRoleGrants", installation)
		teams := listStrings(viewer, "team_ids")
		var direct []string
		for _, g := range listMsgs(held, "grants") {
			if slices.Contains(teams, str(g, "team_id")) {
				t.Fatalf("required conformance fixture invalid: the staleness probe needs the viewer to hold %s's roles only directly; team %s holds %s", f.InstalledSolution, str(g, "team_id"), str(g, "role"))
			}
			if str(g, "person_id") == str(viewer, "person_id") {
				direct = append(direct, str(g, "role"))
			}
		}
		role := func(name string) map[string]any {
			return map[string]any{"organization_id": f.Organization, "installation_id": f.InstalledSolution, "role": name, "person_id": str(viewer, "person_id")}
		}
		if len(direct) == 0 {
			c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "GrantRole", role("viewer"))
		}
		revokedToken := str(c.must(t, as(ctx, viewer), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.InstalledAudience}), "token")
		for _, name := range append(slices.Clone(direct), "viewer") {
			c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "RevokeRole", role(name))
		}
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": revokedToken, "audience": f.InstalledAudience})
		refused(t, err, codes.PermissionDenied, "revoked")
		for _, name := range direct {
			c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "GrantRole", role(name))
		}
	})
	t.Run("every refusal reaches the caller with a reason", func(t *testing.T) {
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience})
		if code := status.Code(err); code != codes.PermissionDenied && code != codes.Unauthenticated {
			t.Fatalf("a person-owned issue with no bearer: %v", err)
		}
		forged := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer no-such-session")
		_, err = c.call(forged, "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience})
		if code := status.Code(err); code != codes.NotFound && code != codes.Unauthenticated {
			t.Fatalf("a bearer no sign-in opened: %v", err)
		}
		// An uncomposed audience is refused by name, for a caller who is otherwise
		// in order: an implementation may refuse an unauthenticated caller first.
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		read := []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read"}}}
		_, err = c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": "not-composed", "scopes": read})
		if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "not-composed") {
			t.Fatalf("an uncomposed audience is named: %v", err)
		}
		_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": "garbage", "audience": f.Audience})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("garbage token: %v", err)
		}
	})
	c.workloadOrganizations(t, ctx, f.WorkloadOrganizations)
	t.Run("a workload is issued its own binding and nothing it did not declare", func(t *testing.T) {
		workload := map[string]any{"workload": map[string]any{"credential": f.WorkloadCredential}, "audience": f.BindingAudience, "organization_id": f.Organization}
		req := clone(workload)
		req["operation_binding_id"] = f.Binding
		out := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", req)
		wc := msg(out, "context")
		if str(wc, "owner_principal_kind") != "service" || str(msg(wc, "operation_binding"), "binding_id") == "" {
			t.Fatalf("workload context = %v", wc)
		}
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.BindingAudience})
		req = clone(workload)
		req["operation_binding_id"] = "undeclared"
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req)
		if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("an undeclared binding is refused by name: %v", err)
		}
		req = clone(workload)
		req["workload"] = map[string]any{"credential": "forged.credential"}
		req["operation_binding_id"] = f.Binding
		_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a forged credential: %v", err)
		}
	})
	t.Run("an installation acts for itself", func(t *testing.T) {
		if f.InstalledCredential == "" {
			t.Fatal("fixture must supply the installed solution workload credential")
		}
		if f.InstalledAudience == "" {
			t.Fatal("fixture must name the installed solution audience")
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		list := c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization})
		var installation protoreflect.Message
		for _, i := range listMsgs(list, "installations") {
			if str(i, "id") == f.InstalledSolution {
				installation = i
			}
		}
		// The principal the installation acts as for itself.
		if installation == nil || enumName(installation, "status") != "STATUS_ACTIVE" || installationPrincipal(installation) == "" {
			t.Fatalf("installed solution = %v", installation)
		}
		out := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"installation": map[string]any{"installation_id": str(installation, "id")}, "audience": f.InstalledAudience, "actor": map[string]any{"credential": f.InstalledCredential}})
		if str(msg(out, "context"), "owner_principal_id") != installationPrincipal(installation) {
			t.Fatalf("installation issue: %v", out)
		}
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.InstalledAudience})
		// The independent organisation role catalogue cannot grant this installation
		// authority at an unrelated module merely because a role label matches.
		if f.InstalledAudience != f.Audience {
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"installation": map[string]any{"installation_id": str(installation, "id")}, "audience": f.Audience, "actor": map[string]any{"credential": f.InstalledCredential}})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("installation acquired unrelated organisation-role authority: %v", err)
			}
		}
	})
	t.Run("an installation issue authenticates its own solution workload", func(t *testing.T) {
		for _, credential := range []string{"", "forged-workload", f.WorkloadCredential} {
			if credential != "" && credential == f.InstalledCredential {
				t.Fatal("fixture must provide a different module workload")
			}
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"installation": map[string]any{"installation_id": f.InstalledSolution}, "audience": f.InstalledAudience, "actor": map[string]any{"credential": credential}})
			if status.Code(err) != codes.PermissionDenied && status.Code(err) != codes.Unauthenticated {
				t.Fatalf("unproven installation caller: %v", err)
			}
		}
	})
	t.Run("a module tool binding carries the person's solution role", func(t *testing.T) {
		if f.SolutionTools == nil {
			t.Fatal("required conformance fixture missing: fixture supplies no module-to-solution tool case")
		}
		c.solutionTools(t, ctx, f, *f.SolutionTools)
	})
	t.Run("a child hop attenuates and names its actor and its binding", func(t *testing.T) {
		// The hop rule: a module hops only on a token addressed to it, and the hop
		// names the binding it exercises, so the child is sealed within the
		// module's installation and carries exactly the binding's scopes the
		// person holds. The person's token therefore names the binding too.
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		parent := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.WorkloadModule, "operation_binding_id": f.Binding})
		read := []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read"}}}
		hop := map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": f.WorkloadCredential},
			"audience": f.BindingAudience, "operation_binding_id": f.Binding}
		req := clone(hop)
		req["scopes"] = read
		child := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", req)
		wc := msg(child, "context")
		if len(listMsgs(wc, "actor_chain")) != 1 || str(wc, "audience") != f.BindingAudience {
			t.Fatalf("child: %v", child)
		}
		// The binding it exercises is named within the organisation and the
		// module acting, since a binding's id is that module's own: a caller
		// holds a child to the binding it asked for by this name.
		if want := f.Organization + "/" + f.WorkloadModule + "/" + f.Binding; str(msg(wc, "operation_binding"), "binding_id") != want {
			t.Fatalf("the child exercises %q, want %q", str(msg(wc, "operation_binding"), "binding_id"), want)
		}
		// And it descends from the context it was asked from: its parent session
		// is that context's own, which a caller holding the parent checks.
		if got, want := str(wc, "parent_session_id"), str(msg(parent, "context"), "session_id"); got == "" || got != want {
			t.Fatalf("the child descends from session %q, want the parent's %q", got, want)
		}
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(child, "token"), "audience": f.BindingAudience})
		req = clone(hop)
		req["scopes"] = []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"admin"}}}
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("widening: %v", err)
		}
		req = clone(hop)
		delete(req, "operation_binding_id")
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.PermissionDenied && status.Code(err) != codes.NotFound {
			t.Fatalf("a hop without a binding must be refused: %v", err)
		}
		req = clone(hop)
		req["operation_binding_id"] = "undeclared"
		req["scopes"] = read
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("an undeclared binding on a hop is refused by name: %v", err)
		}
		elsewhere := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience, "scopes": read})
		req = clone(hop)
		req["parent_token"] = str(elsewhere, "token")
		req["scopes"] = read
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a module hops only on a token addressed to it: %v", err)
		}
	})
	t.Run("a delegate chain inherits the owner's authority at each audience", func(t *testing.T) {
		if f.Chain == nil || len(f.Chain.Hops) < 2 {
			t.Fatal("required conformance fixture missing: the fixture states no delegate chain")
		}
		ch := f.Chain
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": ch.Token})
		token := str(c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": ch.Start}), "token")
		for n, h := range ch.Hops {
			out := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": token,
				"actor": map[string]any{"credential": h.Credential}, "operation_binding_id": h.Binding, "audience": h.Audience,
				"scopes": []any{map[string]any{"resource_kind": h.AskKind, "actions": []any{h.AskAction}}}})
			wc := msg(out, "context")
			if str(wc, "owner_principal_id") != str(sess, "person_id") || len(listMsgs(wc, "actor_chain")) != n+1 || str(wc, "audience") != h.Audience {
				t.Fatalf("hop %d: owner, actors and audience: %v", n+1, wc)
			}
			c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": h.Audience})
			token = str(out, "token")
		}
		last := ch.Hops[len(ch.Hops)-1]
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": token,
			"actor": map[string]any{"credential": last.Credential}, "operation_binding_id": last.Binding, "audience": last.Audience})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a module hops only on a token addressed to it, also down a chain: %v", err)
		}
	})
	t.Run("child target projection preserves explicit delegation restrictions", func(t *testing.T) {
		if f.ChildScopes == nil {
			t.Fatal("required conformance fixture missing: the fixture states no child-scope case")
		}
		c.childScopes(t, ctx, *f.ChildScopes)
	})
	t.Run("an installation owner survives successive module actors", func(t *testing.T) {
		if f.InstallationChain == nil {
			t.Fatal("required conformance fixture missing: the fixture states no installation-owned chain")
		}
		c.installationChain(t, ctx, f, *f.InstallationChain)
	})
	t.Run("installation-owned role scopes cover only what the installation owns", func(t *testing.T) {
		c.installationResources(t, ctx, f)
	})
	t.Run("a check naming a method applies what the module's delivery declares", func(t *testing.T) {
		if f.SignManifest == nil || f.SignAuthority == nil {
			t.Fatal("required conformance fixture missing: the fixture signs no authority document")
		}
		const module = "conformance-methods"
		read := []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read"}}}
		write := []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"write"}}}
		methods := []any{
			map[string]any{"method": "/conformance.Service/Read", "requires": read},
			map[string]any{"method": "/conformance.Service/Write", "requires": write},
			map[string]any{"method": "/conformance.Service/Open", "any_checked_caller": true},
			map[string]any{"method": "/conformance.Service/Unmarked"},
		}
		if _, err := c.deliverWithMethods(ctx, f, module, 1, []string{f.ReadKind}, methods, 0); err != nil {
			t.Fatalf("deliver with the authority's document: %v", err)
		}
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		token := str(c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": module}), "token")
		check := func(method string) error {
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": module, "method": method})
			return err
		}
		for method, want := range map[string]codes.Code{
			"": codes.OK, "/conformance.Service/Read": codes.OK, "/conformance.Service/Open": codes.OK,
			"/conformance.Service/Write": codes.PermissionDenied, "/conformance.Service/Unmarked": codes.PermissionDenied,
			"/conformance.Service/Missing": codes.NotFound,
		} {
			t.Run("method policy "+method, func(t *testing.T) {
				err := check(method)
				reason := ""
				if want != codes.OK {
					reason = strings.TrimPrefix(method, "/conformance.Service/")
				}
				refused(t, err, want, reason)
			})
		}
		if f.LocalAdvisory {
			t.Run("advisory preserves the checked context and exact policy refusal", func(t *testing.T) {
				method := "/conformance.Service/Write"
				denied := check(method)
				refused(t, denied, codes.PermissionDenied, "requires")
				request := map[string]any{"token": token, "audience": module, "method": method, "advisory": true}
				advised := c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", request)
				plain := c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": module})
				if str(advised, "refusal") != status.Convert(denied).Message() || !proto.Equal(msg(advised, "context").Interface(), msg(plain, "context").Interface()) || str(advised, "authorization_revision") != str(plain, "authorization_revision") {
					t.Fatal("advisory changed verified authority or lost the exact refusal")
				}
				request["token"] = "invalid-token"
				_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", request)
				refused(t, err, codes.Unauthenticated, "")
			})
		}

		// A document that does not match the manifest it travels with is refused,
		// and the module keeps the policy it had.
		if _, err := c.deliverWithMethods(ctx, f, module, 2, []string{f.ReadKind}, []any{map[string]any{"method": "/conformance.Service/Write", "any_checked_caller": true}}, 1); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("an authority document for another generation: %v", err)
		}
		if status.Code(check("/conformance.Service/Write")) != codes.PermissionDenied {
			t.Fatal("a refused delivery must not loosen the module's policy")
		}
		// A delivery without the document leaves no method policy: fail closed.
		if _, err := c.applyManifest(ctx, f, module, "module", 3, []string{f.ReadKind}); err != nil {
			t.Fatalf("deliver without the document: %v", err)
		}
		token = str(c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": module}), "token")
		if status.Code(check("/conformance.Service/Read")) != codes.PermissionDenied || check("") != nil {
			t.Fatal("with no document delivered, a check naming a method is refused and one naming none is not")
		}
	})
	t.Run("the authority answers which resources a context covers, by grant", func(t *testing.T) {
		rc := f.Resources
		if rc == nil {
			t.Fatal("required conformance fixture missing: the fixture states no resource case")
		}
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": rc.Token})
		issue := func(scopes []any) (protoreflect.Message, error) {
			fields := map[string]any{"person": map[string]any{}, "audience": rc.Audience}
			if scopes != nil {
				fields["scopes"] = scopes
			}
			return c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", fields)
		}
		list := func(token, action string) (*resources.Matcher, error) {
			out, err := c.call(ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{
				"token": token, "audience": rc.Audience, "resource_kind": rc.Kind, "action": action})
			if err != nil {
				return nil, err
			}
			return resources.Compile(grantsOf(out))
		}
		// A context asking for the covered ids carries them: the authority
		// answers each covered and none of the uncovered.
		out, err := issue([]any{scopeAsk(rc.Kind, []string{rc.Action}, rc.Covered)})
		if err != nil {
			t.Fatalf("issue on the covered ids: %v", err)
		}
		covered, err := list(str(out, "token"), rc.Action)
		if err != nil {
			t.Fatalf("list %s:%s: %v", rc.Kind, rc.Action, err)
		}
		for _, id := range rc.Covered {
			if !covered.Matches(id) {
				t.Errorf("%s is not covered", id)
			}
		}
		for _, id := range rc.Uncovered {
			if covered.Matches(id) {
				t.Errorf("%s is covered", id)
			}
		}
		if covered.All() {
			t.Error("a context on named ids covers the whole kind")
		}
		if _, err := list(str(out, "token"), rc.Unheld); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("an action the context does not hold: %v", err)
		}
		// An empty ask never carries the kind whole: a module deciding from
		// the context's claims would read it as every resource. Each row of
		// the kind it carries names ids, none of them uncovered.
		if out, err := issue(nil); err == nil {
			for _, row := range listMsgs(msg(out, "context"), "authority_scopes") {
				if str(row, "resource_kind") != rc.Kind || field(row, "actions").List().Len() == 0 {
					continue
				}
				ids := field(row, "resource_ids").List()
				if ids.Len() == 0 {
					t.Fatalf("an empty ask carries the whole of %s", rc.Kind)
				}
				for i := 0; i < ids.Len(); i++ {
					if slices.Contains(rc.Uncovered, ids.Get(i).String()) {
						t.Fatalf("an empty ask carries %s, which the person does not hold", ids.Get(i).String())
					}
				}
			}
		} else if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("an empty ask: %v", err)
		}
		// An ask naming an uncovered id is refused, even beside a covered one,
		// and so is an ask for the whole kind.
		if len(rc.Covered) > 0 && len(rc.Uncovered) > 0 {
			_, err := issue([]any{scopeAsk(rc.Kind, []string{rc.Action}, []string{rc.Covered[0], rc.Uncovered[0]})})
			refused(t, err, codes.PermissionDenied, "widens")
		}
		_, err = issue([]any{scopeAsk(rc.Kind, []string{rc.Action}, nil)})
		refused(t, err, codes.PermissionDenied, "what the owner holds")
	})
	t.Run("a lookup through a binding carries only the binding's lookup scopes", func(t *testing.T) {
		lc := f.Lookup
		if lc == nil {
			t.Fatal("required conformance fixture missing: the fixture states no lookup case")
		}
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": lc.Token})
		parent := str(c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": lc.Start}), "token")
		hop := func(operation string) string {
			out := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
				"parent_token": parent, "audience": lc.Audience, "actor": map[string]any{"credential": lc.Credential},
				"operation_binding_id": lc.Binding, "operation": operation})
			return scopeActions(msg(out, "context"), lc.Kind)
		}
		if got := hop("invoke"); !strings.Contains(got, lc.Invoke) {
			t.Fatalf("invoke carries %q, want %s", got, lc.Invoke)
		}
		if got := hop("lookup"); got != lc.Lookup {
			t.Fatalf("lookup carries %q, want only %s", got, lc.Lookup)
		}
	})
	t.Run("a delegation issues as its grantor through its module, until revoked", func(t *testing.T) {
		dc := f.Delegation
		if dc == nil {
			t.Fatal("required conformance fixture missing: the fixture states no delegation case")
		}
		scopes := []any{map[string]any{"resource_kind": dc.Kind, "actions": []any{dc.Action}}}
		grantor := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": dc.Token})
		outsider := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": dc.Outsider})
		if _, err := c.call(as(ctx, outsider), "host.authority.v1.AuthorityService", "Delegate", map[string]any{"module": dc.Module, "scopes": scopes, "purpose": "conformance"}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a person delegates what they do not hold: %v", err)
		}
		d := c.must(t, as(ctx, grantor), "host.authority.v1.AuthorityService", "Delegate", map[string]any{"module": dc.Module, "scopes": scopes, "purpose": "conformance"})
		id := str(d, "delegation_id")
		issue := func() (protoreflect.Message, error) {
			return c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
				"delegation": map[string]any{"delegation_id": id}, "audience": dc.Audience,
				"actor": map[string]any{"credential": dc.Credential}, "operation_binding_id": dc.Binding})
		}
		out, err := issue()
		if err != nil {
			t.Fatalf("issue from the delegation: %v", err)
		}
		wc := msg(out, "context")
		if str(wc, "owner_principal_id") != str(grantor, "person_id") || !strings.Contains(scopeActions(wc, dc.Kind), dc.Action) {
			t.Fatalf("issued for %q with %q", str(wc, "owner_principal_id"), scopeActions(wc, dc.Kind))
		}
		chain := field(wc, "actor_chain").List()
		if chain.Len() != 1 || str(chain.Get(0).Message(), "delegation_id") != id || str(chain.Get(0).Message(), "principal_id") != dc.Module {
			t.Fatalf("the module acts under the delegation: %v", wc)
		}
		read := func(caller context.Context, actor string) (protoreflect.Message, error) {
			req := map[string]any{"delegation_id": id}
			if actor != "" {
				req["actor"] = map[string]any{"credential": actor}
			}
			return c.call(caller, "host.authority.v1.AuthorityService", "GetDelegation", req)
		}
		for name, caller := range map[string]struct {
			ctx   context.Context
			actor string
		}{"its module": {ctx, dc.Credential}, "its grantor": {as(ctx, grantor), ""}} {
			if got, err := read(caller.ctx, caller.actor); err != nil || !field(got, "active").Bool() {
				t.Fatalf("%s reads the delegation as not standing: %v", name, err)
			}
		}
		if _, err := read(as(ctx, outsider), ""); status.Code(err) != codes.NotFound {
			t.Fatalf("anyone else learns the delegation exists: %v", err)
		}
		c.must(t, as(ctx, grantor), "host.authority.v1.AuthorityService", "RevokeDelegation", map[string]any{"delegation_id": id})
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": dc.Audience}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("authority issued before delegation revocation still checks: %v", err)
		}
		if _, err := issue(); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a revoked delegation issues: %v", err)
		}
		if got, err := read(ctx, dc.Credential); err != nil || field(got, "active").Bool() {
			t.Fatalf("its module reads a revoked delegation as standing: %v", err)
		}
	})
	t.Run("a delegation asked for with a lifetime carries when it ends and ends then, and none asked carries none", func(t *testing.T) {
		dc := f.Delegation
		if dc == nil {
			t.Fatal("required conformance fixture missing: the fixture states no delegation case")
		}
		scopes := []any{map[string]any{"resource_kind": dc.Kind, "actions": []any{dc.Action}}}
		grantor := as(ctx, c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": dc.Token}))
		delegate := func(ttl int64) (protoreflect.Message, error) {
			return c.call(grantor, "host.authority.v1.AuthorityService", "Delegate", map[string]any{"module": dc.Module, "scopes": scopes, "purpose": "conformance lifetime", "ttl_seconds": ttl})
		}
		if _, err := delegate(-1); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("a negative lifetime: %v", err)
		}
		for _, ttl := range []int64{3600, 0} {
			d, err := delegate(ttl)
			if err != nil {
				t.Fatalf("delegate for %d s: %v", ttl, err)
			}
			at := field(d, "expires_at_unix").Int()
			if (ttl > 0) != (at > 0) {
				t.Fatalf("a delegation asked for %d s ends at %d", ttl, at)
			}
			got, err := c.call(ctx, "host.authority.v1.AuthorityService", "GetDelegation", map[string]any{"delegation_id": str(d, "delegation_id"), "actor": map[string]any{"credential": dc.Credential}})
			if err != nil || field(got, "expires_at_unix").Int() != at || !field(got, "active").Bool() {
				t.Fatalf("its module reads a delegation asked for %d s as ending at %d, standing %v: %v", ttl, field(got, "expires_at_unix").Int(), field(got, "active").Bool(), err)
			}
			c.must(t, grantor, "host.authority.v1.AuthorityService", "RevokeDelegation", map[string]any{"delegation_id": str(d, "delegation_id")})
		}

		// The host enforces the end, not only reports it: a one-second
		// delegation issues, and once past it neither issues nor reads as
		// standing. The suite cannot move a host's clock, so it waits.
		d, err := delegate(1)
		if err != nil {
			t.Fatalf("delegate for 1 s: %v", err)
		}
		id := str(d, "delegation_id")
		issue := func() error {
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
				"delegation": map[string]any{"delegation_id": id}, "audience": dc.Audience,
				"actor": map[string]any{"credential": dc.Credential}, "operation_binding_id": dc.Binding})
			return err
		}
		if err := issue(); err != nil {
			t.Fatalf("a standing one-second delegation does not issue: %v", err)
		}
		time.Sleep(1500 * time.Millisecond)
		if err := issue(); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("an expired delegation issues: %v", err)
		}
		got, err := c.call(ctx, "host.authority.v1.AuthorityService", "GetDelegation", map[string]any{"delegation_id": id, "actor": map[string]any{"credential": dc.Credential}})
		if err != nil || field(got, "active").Bool() {
			t.Fatalf("its module reads an expired delegation as standing: %v", err)
		}
	})
	t.Run("a manifest moves only forward and a lower generation is refused by name", func(t *testing.T) {
		if _, err := c.applyManifest(ctx, f, "conformance-probe", "module", 2, []string{"probe"}); err != nil {
			t.Fatalf("apply: %v", err)
		}
		_, err := c.applyManifest(ctx, f, "conformance-probe", "module", 1, []string{"probe"})
		refused(t, err, codes.FailedPrecondition, "generation")
	})
	c.resourceMethod(t, ctx, f)
	c.installationLifecycle(t, ctx, f)
	c.organizationIsolation(t, ctx, f)
	c.admissionKeys(t, ctx, f)
}

// scopeActions is a context's actions on kind, comma-joined.
func scopeActions(wc protoreflect.Message, kind string) string {
	list := field(wc, "authority_scopes").List()
	for i := 0; i < list.Len(); i++ {
		sc := list.Get(i).Message()
		if str(sc, "resource_kind") != kind {
			continue
		}
		var out []string
		actions := field(sc, "actions").List()
		for j := 0; j < actions.Len(); j++ {
			out = append(out, actions.Get(j).String())
		}
		return strings.Join(out, ",")
	}
	return ""
}

// grantsOf reads a ListResourcesResponse's grants as the shared library's.
func grantsOf(m protoreflect.Message) []resources.Grant {
	var out []resources.Grant
	list := field(m, "grants").List()
	for i := 0; i < list.Len(); i++ {
		g := list.Get(i).Message()
		out = append(out, resources.Grant{
			All: g.Get(g.Descriptor().Fields().ByName("all")).Bool(), ID: str(g, "id"), Prefix: str(g, "prefix"), Pattern: str(g, "pattern"),
		})
	}
	return out
}

// --- the dynamic client -----------------------------------------------------

type client struct {
	conn  grpc.ClientConnInterface
	files *protoregistry.Files
}

func newClient(conn grpc.ClientConnInterface, descriptors []byte) (*client, error) {
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(descriptors, &set); err != nil {
		return nil, fmt.Errorf("descriptor set: %w", err)
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return nil, fmt.Errorf("descriptor set: %w", err)
	}
	return &client{conn: conn, files: files}, nil
}

func (c *client) method(service, method string) (protoreflect.MethodDescriptor, error) {
	d, err := c.files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return nil, fmt.Errorf("service %s: %w", service, err)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is not a service", service)
	}
	md := sd.Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return nil, fmt.Errorf("%s has no method %s", service, method)
	}
	return md, nil
}

func (c *client) call(ctx context.Context, service, method string, fields map[string]any) (protoreflect.Message, error) {
	md, err := c.method(service, method)
	if err != nil {
		return nil, err
	}
	req := dynamicpb.NewMessage(md.Input())
	if err := fill(req, fields); err != nil {
		return nil, err
	}
	resp := dynamicpb.NewMessage(md.Output())
	if err := c.conn.Invoke(ctx, "/"+service+"/"+method, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *client) must(t *testing.T, ctx context.Context, service, method string, fields map[string]any) protoreflect.Message {
	t.Helper()
	out, err := c.call(ctx, service, method, fields)
	if err != nil {
		t.Fatalf("%s/%s: %v", service, method, err)
	}
	return out
}

func fill(m *dynamicpb.Message, fields map[string]any) error {
	for name, value := range fields {
		fd := m.Descriptor().Fields().ByName(protoreflect.Name(name))
		if fd == nil {
			return fmt.Errorf("%s has no field %s", m.Descriptor().FullName(), name)
		}
		v, err := toValue(m, fd, value)
		if err != nil {
			return err
		}
		m.Set(fd, v)
	}
	return nil
}

func toValue(m *dynamicpb.Message, fd protoreflect.FieldDescriptor, value any) (protoreflect.Value, error) {
	if fd.IsList() {
		items, ok := value.([]any)
		if !ok {
			return protoreflect.Value{}, fmt.Errorf("%s is a list", fd.FullName())
		}
		l := m.NewField(fd).List()
		for _, item := range items {
			v, err := scalar(fd, item, l.NewElement)
			if err != nil {
				return protoreflect.Value{}, err
			}
			l.Append(v)
		}
		return protoreflect.ValueOfList(l), nil
	}
	return scalar(fd, value, func() protoreflect.Value { return m.NewField(fd) })
}

func scalar(fd protoreflect.FieldDescriptor, value any, fresh func() protoreflect.Value) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.MessageKind:
		sub, ok := value.(map[string]any)
		if !ok {
			return protoreflect.Value{}, fmt.Errorf("%s is a message", fd.FullName())
		}
		v := fresh()
		if err := fill(v.Message().(*dynamicpb.Message), sub); err != nil {
			return protoreflect.Value{}, err
		}
		return v, nil
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(value.(string)), nil
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(value.([]byte)), nil
	case protoreflect.Uint64Kind:
		return protoreflect.ValueOfUint64(value.(uint64)), nil
	case protoreflect.Int64Kind:
		return protoreflect.ValueOfInt64(value.(int64)), nil
	case protoreflect.Int32Kind:
		return protoreflect.ValueOfInt32(value.(int32)), nil
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(value.(bool)), nil
	}
	return protoreflect.Value{}, fmt.Errorf("%s: unsupported kind %s", fd.FullName(), fd.Kind())
}

func field(m protoreflect.Message, name string) protoreflect.Value {
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(name))
	if fd == nil {
		return protoreflect.Value{}
	}
	return m.Get(fd)
}
func str(m protoreflect.Message, name string) string {
	v := field(m, name)
	if !v.IsValid() {
		return ""
	}
	return v.String()
}
func u64(m protoreflect.Message, name string) uint64 { return field(m, name).Uint() }
func i64(m protoreflect.Message, name string) int64  { return field(m, name).Int() }
func msg(m protoreflect.Message, name string) protoreflect.Message {
	return field(m, name).Message()
}
func enumName(m protoreflect.Message, name string) string {
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(name))
	return string(fd.Enum().Values().ByNumber(m.Get(fd).Enum()).Name())
}

// count is the length of a repeated field, of messages or scalars alike.
func count(m protoreflect.Message, name string) int { return field(m, name).List().Len() }

// listMsgs are the messages of a repeated message field.
func listMsgs(m protoreflect.Message, name string) []protoreflect.Message {
	l := field(m, name).List()
	out := make([]protoreflect.Message, 0, l.Len())
	for i := 0; i < l.Len(); i++ {
		out = append(out, l.Get(i).Message())
	}
	return out
}

func clone(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func as(ctx context.Context, session protoreflect.Message) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+str(session, "bearer"))
}
