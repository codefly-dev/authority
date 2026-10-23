// Package conformance is the suite every implementation of the host interfaces
// must pass: the mini gateway and the host's accounts alike. It links no
// generated Go package, because an implementation links its own and a second
// registration of the same proto file panics; it drives the interfaces from
// their published descriptors (the contract.binpb codefly generate writes) with
// dynamic messages over any gRPC connection.
package conformance

import (
	"context"
	"fmt"
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
	Organization       string // the one organisation the people belong to
	ViewerToken        string // signs in a person who may read ReadKind at Audience and nothing more
	AdminToken         string // signs in an organisation administrator
	Audience           string // a composed module the viewer holds "read" on
	ReadKind           string // the resource kind the viewer may read at Audience
	WorkloadModule     string // the principal of the module WorkloadCredential names; a person's token for its hop is addressed here
	WorkloadCredential string // the credential of a composed module's workload; the module declares Binding, addressed to BindingAudience
	Binding            string // the workload module's operation binding whose invoke scopes cover "read" on ReadKind
	BindingAudience    string // the audience Binding is addressed to; a hop exercising Binding is addressed here
	Elsewhere          string // a composed audience the viewer's context at Audience is not addressed to
	InstalledSolution  string // an active installation the viewer is entitled to

	// A delivery, as Codefly signs it. When SignManifest is set the suite applies
	// manifests as signed carriers: core's module manifest for HostCoordinate and
	// HostDomain, signed by SignManifest, carried by DeliveryCredential(module).
	// Nil applies the sketch, which the transition still allows.
	HostCoordinate     string
	HostDomain         string
	SignManifest       func(document []byte) (envelope []byte, err error)
	DeliveryCredential func(module string) string

	// SlowChecks runs the lines that must wait on the clock, such as a token
	// expiring past core's skew; off by default.
	SlowChecks bool

	// Matrix is the permission matrix the fixture states: for each person, at
	// each audience, each kind and action is allowed or refused. The suite asks
	// for exactly that scope and expects the answer, so every role a fixture
	// declares is proven allow and deny.
	Matrix []Expectation
}

// Expectation is one cell of the permission matrix.
type Expectation struct {
	Token    string // the person's fixture token
	Audience string
	Kind     string
	Action   string
	Allowed  bool
}

// applyManifest composes one module at one generation, as a signed carrier when
// the fixture signs, as the sketch otherwise.
func (c *client) applyManifest(ctx context.Context, f Fixture, alias, kind string, generation uint64, kinds []string) (protoreflect.Message, error) {
	// Core's manifest carries no roles yet, so a solution is composed through the
	// sketch, declaring its installer and viewer roles over what it serves.
	if f.SignManifest == nil || kind == "solution" {
		var roles []any
		if kind == "solution" {
			var all, reads []any
			for _, k := range kinds {
				all = append(all, map[string]any{"resource_kind": k, "actions": []any{"read", "write"}})
				reads = append(reads, map[string]any{"resource_kind": k, "actions": []any{"read"}})
			}
			roles = []any{map[string]any{"name": "installer", "scopes": all}, map[string]any{"name": "viewer", "scopes": reads}}
		}
		var rks []any
		for _, k := range kinds {
			rks = append(rks, map[string]any{"kind": k, "actions": []any{"read", "write"}})
		}
		manifest := map[string]any{"module": alias, "principal": alias, "kind": kind, "generation": generation, "resource_kinds": rks}
		if roles != nil {
			manifest["roles"] = roles
		}
		return c.call(ctx, "host.composition.v1.CompositionService", "ApplyManifest", map[string]any{"manifest": manifest})
	}
	manifest := &solutionhost.ModuleManifest{
		Schema: solutionhost.SchemaModuleManifestV1, Binding: alias, Alias: alias, Kind: solutionhost.Kind(kind), Generation: generation,
		Host:      solutionhost.HostTarget{Coordinate: f.HostCoordinate, Domain: f.HostDomain},
		Release:   solutionhost.Release{Publisher: "conformance", Name: alias, Version: "0.1.0"},
		Workloads: []solutionhost.Workload{{Service: "api", Container: "app"}},
		Authority: &solutionhost.Authority{Principal: alias, ResourceKinds: kinds},
	}
	document, err := solutionhost.SignedPayload(manifest)
	if err != nil {
		return nil, err
	}
	envelope, err := f.SignManifest(document)
	if err != nil {
		return nil, err
	}
	return c.call(ctx, "host.composition.v1.CompositionService", "ApplyManifest", map[string]any{
		"carrier": map[string]any{"document": document, "envelope": envelope}, "credential": f.DeliveryCredential(alias)})
}

// Run drives the suite over one connection, from the published descriptors.
func Run(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f Fixture) {
	t.Helper()
	c, err := newClient(conn, descriptors)
	if err != nil {
		t.Fatalf("conformance: %v", err)
	}
	ctx := context.Background()

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
			t.Skip("the fixture states no matrix")
		}
		sessions := map[string]protoreflect.Message{}
		for _, e := range f.Matrix {
			sess, ok := sessions[e.Token]
			if !ok {
				sess = c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": e.Token})
				sessions[e.Token] = sess
			}
			_, err := c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": e.Audience,
				"scopes": []any{map[string]any{"resource_kind": e.Kind, "actions": []any{e.Action}}}})
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
		// opt-in (SlowChecks); the fast check asserts the window the token states.
		short := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience, "scopes": read, "ttl_seconds": int64(1)})
		if i64(msg(short, "context"), "expires_at_unix")-i64(msg(short, "context"), "issued_at_unix") > 1 {
			t.Fatalf("a one-second window is issued as asked: %v", msg(short, "context"))
		}
		if f.SlowChecks {
			time.Sleep(workcontext.DefaultSkew + 2*time.Second)
			if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(short, "token"), "audience": f.Audience}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("an expired token is Unauthenticated: %v", err)
			}
		}
		if f.InstalledSolution == "" {
			t.Skip("staleness needs an installation whose grant can move")
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		before := c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": f.Audience})
		c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "GrantToTeam", map[string]any{"organization_id": f.Organization, "installation_id": f.InstalledSolution, "team_id": "callee-probe-" + str(before, "authorization_revision")})
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": f.Audience})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a token sealed before the organisation's authority moved is stale, refused as PermissionDenied: %v", err)
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
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		list := c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization})
		var wiki protoreflect.Message
		for _, i := range listMsgs(list, "installations") {
			if str(i, "id") == f.InstalledSolution {
				wiki = i
			}
		}
		if wiki == nil || enumName(wiki, "status") != "STATUS_ACTIVE" || str(wiki, "agent_principal_id") == "" {
			t.Fatalf("installed solution = %v", wiki)
		}
		out := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"installation": map[string]any{"installation_id": str(wiki, "id")}, "audience": f.Audience})
		if str(msg(out, "context"), "owner_principal_id") != str(wiki, "agent_principal_id") {
			t.Fatalf("installation issue: %v", out)
		}
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
		if len(listMsgs(wc, "actor_chain")) != 1 || str(msg(wc, "operation_binding"), "binding_id") == "" || str(wc, "audience") != f.BindingAudience {
			t.Fatalf("child: %v", child)
		}
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(child, "token"), "audience": f.BindingAudience})
		req = clone(hop)
		req["scopes"] = []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"admin"}}}
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("widening: %v", err)
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
	t.Run("a manifest moves only forward and a lower generation is refused by name", func(t *testing.T) {
		if _, err := c.applyManifest(ctx, f, "conformance-probe", "module", 2, []string{"probe"}); err != nil {
			t.Fatalf("apply: %v", err)
		}
		_, err := c.applyManifest(ctx, f, "conformance-probe", "module", 1, []string{"probe"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("lower generation: %v", err)
		}
	})
	t.Run("install is pending until acknowledged, then exposed to a team", func(t *testing.T) {
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		if _, err := c.applyManifest(ctx, f, "conformance-solution", "solution", 1, []string{"conformance.page"}); err != nil {
			t.Fatalf("apply solution: %v", err)
		}
		install := map[string]any{"organization_id": f.Organization, "target": "conformance-solution", "role": "viewer", "owner_person_id": str(admin, "person_id")}
		inst := c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "Install", install)
		if st := enumName(inst, "status"); st != "STATUS_PENDING" && st != "STATUS_ACTIVE" {
			t.Fatalf("install status = %s", st)
		}
		granted := c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "GrantToTeam", map[string]any{"organization_id": f.Organization, "installation_id": str(inst, "id"), "team_id": "finance"})
		if count(granted, "team_ids") != 1 || u64(granted, "revision") != u64(inst, "revision")+1 {
			t.Fatalf("grant: %v", granted)
		}
		_, err := c.call(as(ctx, admin), "host.installation.v1.InstallationService", "Install", install)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("installing twice: %v", err)
		}
		_, err = c.call(as(ctx, admin), "host.installation.v1.InstallationService", "GrantToTeam", map[string]any{"organization_id": "another-organisation", "installation_id": str(inst, "id"), "team_id": "finance"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a grant naming another organisation: %v", err)
		}
	})
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
