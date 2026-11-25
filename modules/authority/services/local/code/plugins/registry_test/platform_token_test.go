// A user token of the OBIN platform presented to the local authority
// (pkg/business/platformtoken), against a test issuer of those tokens
// (obintoken/obintest): off unless a host installs the gate, the same
// decisions as the platform makes, and a read at a module that ends when the
// role version moves.
package registry_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/codefly-dev/authority/libraries/authority-core/go/obintoken"
	"github.com/codefly-dev/authority/libraries/authority-core/go/obintoken/obintest"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"

	"gateway/pkg/business/platformtoken"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	"gateway/pkg/framework"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	sessionv1 "gateway/pkg/gen/host/session/v1"
	"gateway/plugins/authority"
	"gateway/plugins/installation"
	"gateway/plugins/session"
)

const (
	platformIssuer   = "https://token-exchange.test.invalid"
	platformAudience = "authority-host"
)

var platformFrontDoor = obintest.Actor{Sub: "system:serviceaccount:platform:front-door", Service: "front-door"}

// platformHost is a local authority over the kit's fixture and a platform
// that knows the same people under its own names: tenants org_acme and
// org_globex, users user_<person>, the wiki's roles reader and editor.
type platformHost struct {
	kit    *testkit.Kit
	issuer *obintest.Issuer
	conn   *grpc.ClientConn
}

// platformRoles is the role each person holds in the platform's wiki. It
// mirrors what the kit's composition gives them on this host: the wiki's
// owner is its admin, their teams' members its users, and no-roles nothing.
var platformRoles = map[string]map[string]string{
	"org_acme":   {"alex": "editor", "maya": "reader", "remi": "reader", "no-roles": ""},
	"org_globex": {"zoe": "editor", "omar": "reader"},
}

// newPlatformHost serves the kit's authority, with the gate installed when
// accepting, and a platform issuer on the host's clock.
func newPlatformHost(t *testing.T, accepting bool) *platformHost {
	t.Helper()
	// One clock for the host, the issuer and the module that verifies a
	// capability on the wall clock.
	k := testkit.NewWithClock(t, time.Now)
	issuer := obintest.New(t, platformIssuer, time.Now)
	issuer.Grants("wiki", "reader", "wiki:pages:read")
	issuer.Grants("wiki", "editor", "wiki:pages:read", "wiki:pages:write", "wiki:pages:publish")
	mapping := obintoken.Mapping{
		Tenants:   map[string]string{"org_acme": "acme", "org_globex": "globex"},
		Users:     map[string]map[string]string{"acme": {}, "globex": {}},
		Solutions: map[string]map[string]string{"acme": {"wiki": state.InstallationID("acme", "wiki")}, "globex": {"wiki": state.InstallationID("globex", "wiki")}},
		Roles:     map[string]map[string]string{"wiki": {"reader": state.UserRole, "editor": state.AdminRole}},
		Actors:    map[string]string{platformFrontDoor.Sub: "front-door"},
	}
	for tenant, people := range platformRoles {
		for person, role := range people {
			member := obintest.Member{Status: "active", TenantRole: "member", Solutions: map[string]string{}}
			if role != "" {
				member.Solutions["wiki"] = role
			}
			issuer.SetMember(tenant, "user_"+person, member)
			mapping.Users[mapping.Tenants[tenant]]["user_"+person] = person
		}
	}
	var options []grpc.ServerOption
	if accepting {
		keys, err := obintoken.ParseKeySet(issuer.KeySet())
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := obintoken.New(obintoken.Config{Issuer: platformIssuer, Audience: platformAudience, Keys: keys, Mapping: mapping, SignIns: issuer})
		if err != nil {
			t.Fatal(err)
		}
		gate := &platformtoken.Gate{Adapter: adapter, State: k.State}
		options = append(options, grpc.ChainUnaryInterceptor(gate.UnaryInterceptor()), grpc.ChainStreamInterceptor(gate.StreamInterceptor()))
	}
	server := grpc.NewServer(options...)
	for _, p := range []framework.Plugin{&authority.Plugin{Issuer: k.Issuer}, &installation.Plugin{State: k.State}, &session.Plugin{State: k.State, Fixture: true}} {
		p.RegisterGRPC(server)
	}
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &platformHost{kit: k, issuer: issuer, conn: conn}
}

// mint is the platform's token for person of tenant at the wiki, for this host.
func (h *platformHost) mint(t *testing.T, tenant, person string) string {
	t.Helper()
	token, err := h.issuer.Mint(tenant, "user_"+person, platformAudience, "wiki", platformFrontDoor)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func bearing(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
}

// issue asks the host, as whoever bearer is, for everything they hold at the wiki.
func (h *platformHost) issue(bearer string) (*authorityv1.IssueResponse, error) {
	return authorityv1.NewAuthorityServiceClient(h.conn).Issue(bearing(bearer), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "wiki"})
}

// wikiModule is the wiki as a module downstream of the host: it holds one
// page, verifies a capability offline against the keys the host publishes
// (core's Inspector, the check a module's hop makes; the hop library itself
// links the client's bindings of these protos and cannot share this binary),
// asks the host whether it still stands, and serves the page to a capability
// that reads pages.
type wikiModule struct {
	inspector *workcontext.Inspector
	host      authorityv1.AuthorityServiceClient
	pages     map[string]string
}

func (h *platformHost) wiki(t *testing.T) *wikiModule {
	t.Helper()
	host := authorityv1.NewAuthorityServiceClient(h.conn)
	published, err := host.Keys(t.Context(), &authorityv1.KeysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, key := range published.GetKeys() {
		keys[key.GetKeyId()] = ed25519.PublicKey(key.GetPublicKey())
	}
	return &wikiModule{inspector: &workcontext.Inspector{Issuer: published.GetIssuer(), Keys: keys}, host: host, pages: map[string]string{"handbook": "how we work"}}
}

var errNoSuchAction = errors.New("the capability does not hold the action on wiki.page")

// do is one call on a page: read answers its body.
func (w *wikiModule) do(ctx context.Context, capability, action, page string) (string, error) {
	if _, err := w.inspector.Inspect(capability, "wiki"); err != nil {
		return "", err
	}
	decoded, err := workcontext.Decode(capability)
	if err != nil {
		return "", err
	}
	// What the caller holds here: the last actor's grant, or the owner's own.
	held := decoded.Context().GetAuthorityScopes()
	if chain := decoded.Context().GetActorChain(); len(chain) > 0 {
		held = chain[len(chain)-1].GetGrantedScopes()
	}
	if !slices.ContainsFunc(held, func(s *basev0.WorkScopeV1) bool {
		return s.GetResourceKind() == "wiki.page" && slices.Contains(s.GetActions(), action)
	}) {
		return "", errNoSuchAction
	}
	checked, err := w.host.Check(ctx, &authorityv1.CheckRequest{Token: capability, Audience: "wiki"})
	if err != nil {
		return "", err
	}
	if checked.GetRefusal() != "" {
		return "", errors.New(checked.GetRefusal())
	}
	return w.pages[page], nil
}

func unauthenticated(t *testing.T, err error, reason string) {
	t.Helper()
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(status.Convert(err).Message(), reason) {
		t.Fatalf("want Unauthenticated naming %q, got %v", reason, err)
	}
}

// A host that installs no gate takes a platform token for a bearer that names
// no session, as it always did.
func TestAPlatformTokenIsNoBearerUnlessTheHostAcceptsThem(t *testing.T) {
	t.Parallel()
	h := newPlatformHost(t, false)
	token := h.mint(t, "org_acme", "maya")
	_, err := h.issue(token)
	if err == nil {
		t.Fatal("a host that accepts no platform token issued on one")
	}
	if strings.Contains(status.Convert(err).Message(), "platform token") {
		t.Fatalf("the host read the token: %v", err)
	}
	_, err = sessionv1.NewSessionServiceClient(h.conn).Current(bearing(token), &sessionv1.CurrentRequest{})
	unauthenticated(t, err, "names no open session")
}

// The differential: for every person and every action on a wiki page, the
// platform's own answer (the scope its token for them carries) and this
// host's (what a capability issued on that token holds, at the module) are
// the same answer.
func TestThePlatformAndTheHostDecideTheSame(t *testing.T) {
	t.Parallel()
	h := newPlatformHost(t, true)
	wiki := h.wiki(t)
	want := map[string][]string{
		"org_acme/alex": {"publish", "read", "write"}, "org_acme/maya": {"read"}, "org_acme/remi": {"read"}, "org_acme/no-roles": nil,
		"org_globex/zoe": {"publish", "read", "write"}, "org_globex/omar": {"read"},
	}
	for tenant, people := range platformRoles {
		for person := range people {
			t.Run(tenant+"/"+person, func(t *testing.T) {
				capability := ""
				if issued, err := h.issue(h.mint(t, tenant, person)); err == nil {
					capability = issued.GetToken()
				} else if status.Code(err) != codes.Unauthenticated && status.Code(err) != codes.PermissionDenied {
					t.Fatalf("the host neither issued nor refused: %v", err)
				}
				var allowed []string
				for _, action := range []string{"publish", "read", "write"} {
					platform := h.issuer.Allows(tenant, "user_"+person, "wiki", "wiki:pages:"+action)
					_, err := wiki.do(t.Context(), capability, action, "handbook")
					if host := err == nil; host != platform {
						t.Errorf("%s: the platform says %v and the host %v (%v)", action, platform, host, err)
					}
					if platform {
						allowed = append(allowed, action)
					}
				}
				if !slices.Equal(allowed, want[tenant+"/"+person]) {
					t.Errorf("allowed %v, want %v: the table would agree on anything", allowed, want[tenant+"/"+person])
				}
			})
		}
	}
}

// Where the platform and this host disagree about a person, the host's own
// grants decide and the answer is the narrower: the token is refused whole.
func TestAPlatformRoleThePersonDoesNotHoldHereIsRefused(t *testing.T) {
	t.Parallel()
	h := newPlatformHost(t, true)
	// The platform makes Maya an editor; here she is a user of the wiki.
	h.issuer.SetRole("org_acme", "user_maya", "wiki", "editor")
	_, err := h.issue(h.mint(t, "org_acme", "maya"))
	unauthenticated(t, err, "platform token is refused")
	// The platform gives no-roles the reader role; here they hold nothing.
	h.issuer.SetRole("org_acme", "user_no-roles", "wiki", "reader")
	_, err = h.issue(h.mint(t, "org_acme", "no-roles"))
	unauthenticated(t, err, "platform token is refused")
	// Another tenant's token for a person of this one.
	forged, err := h.issuer.Claims("org_acme", "user_maya", platformAudience, "wiki", platformFrontDoor)
	if err != nil {
		t.Fatal(err)
	}
	forged["tenant_id"] = "org_globex"
	_, err = h.issue(h.issuer.Sign(forged))
	unauthenticated(t, err, "assignment evidence")
}

// The composed case: a platform token, the host's capability, a read at the
// module, and the same token refused once the role version moves.
func TestAPlatformTokenReadsAtAModuleUntilTheRoleVersionMoves(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("at the platform", func(t *testing.T) {
		h := newPlatformHost(t, true)
		wiki := h.wiki(t)
		token := h.mint(t, "org_acme", "maya")
		issued, err := h.issue(token)
		if err != nil {
			t.Fatal(err)
		}
		if body, err := wiki.do(ctx, issued.GetToken(), "read", "handbook"); err != nil || body != "how we work" {
			t.Fatalf("the read: %q, %v", body, err)
		}
		if _, err := wiki.do(ctx, issued.GetToken(), "write", "handbook"); !errors.Is(err, errNoSuchAction) {
			t.Fatalf("a reader's write: %v", err)
		}
		// The session the token is here: Maya's, as the wiki's user alone.
		current, err := sessionv1.NewSessionServiceClient(h.conn).Current(bearing(token), &sessionv1.CurrentRequest{})
		if err != nil {
			t.Fatal(err)
		}
		view := current.GetRoleView()
		if current.GetPersonId() != "maya" || len(view) != 1 || view[0].GetInstallationId() != state.InstallationID("acme", "wiki") || !slices.Equal(view[0].GetRoles(), []string{state.UserRole}) {
			t.Fatalf("the token's session: %v", current)
		}
		// It opens no other session.
		_, err = sessionv1.NewSessionServiceClient(h.conn).OpenTeamCast(bearing(token), &sessionv1.OpenTeamCastRequest{TeamId: "finance"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a cast on a platform token: %v", err)
		}
		// The same token again is the same session.
		if again, err := h.issue(token); err != nil {
			t.Fatal(err)
		} else if again.GetContext().GetSessionId() != issued.GetContext().GetSessionId() {
			t.Fatalf("the same token opened another session: %s, then %s", issued.GetContext().GetSessionId(), again.GetContext().GetSessionId())
		}

		// The platform takes Maya's role away: her roles version moves.
		h.issuer.SetRole("org_acme", "user_maya", "wiki", "")
		_, err = h.issue(token)
		unauthenticated(t, err, "role version moved")
		// What the token was issued before ends with it, at the module.
		if body, err := wiki.do(ctx, issued.GetToken(), "read", "handbook"); err == nil {
			t.Fatalf("the capability issued before the move still read %q", body)
		}
		// Given the role back, the old token stays refused.
		h.issuer.SetRole("org_acme", "user_maya", "wiki", "reader")
		_, err = h.issue(token)
		unauthenticated(t, err, "platform token is refused")
	})
	t.Run("on this host", func(t *testing.T) {
		h := newPlatformHost(t, true)
		wiki := h.wiki(t)
		token := h.mint(t, "org_acme", "maya")
		before, err := sessionv1.NewSessionServiceClient(h.conn).Current(bearing(token), &sessionv1.CurrentRequest{})
		if err != nil {
			t.Fatal(err)
		}
		issued, err := h.issue(token)
		if err != nil {
			t.Fatal(err)
		}
		if body, err := wiki.do(ctx, issued.GetToken(), "read", "handbook"); err != nil || body != "how we work" {
			t.Fatalf("the read: %q, %v", body, err)
		}
		// Maya leaves the team the wiki's user role was granted to: the
		// platform has seen nothing, and this host's own grants moved.
		if err := h.kit.State.LeaveTeam(ctx, "maya", "finance"); err != nil {
			t.Fatal(err)
		}
		if body, err := wiki.do(ctx, issued.GetToken(), "read", "handbook"); err == nil {
			t.Fatalf("the capability issued before the role was lost still read %q", body)
		} else if !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("refused, not naming the revocation: %v", err)
		}
		if again, err := h.issue(token); err == nil {
			t.Fatalf("the same token was issued %v after the role was lost", again.GetContext().GetAuthorityScopes())
		}
		after, err := sessionv1.NewSessionServiceClient(h.conn).Current(bearing(token), &sessionv1.CurrentRequest{})
		if err == nil && after.GetGrantEpoch() == before.GetGrantEpoch() {
			t.Fatalf("the grant epoch did not move: %s", after.GetGrantEpoch())
		}
	})
	t.Run("a refused token leaves another person's standing", func(t *testing.T) {
		h := newPlatformHost(t, true)
		wiki := h.wiki(t)
		maya, alex := h.mint(t, "org_acme", "maya"), h.mint(t, "org_acme", "alex")
		held, err := h.issue(alex)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.issue(maya); err != nil {
			t.Fatal(err)
		}
		h.issuer.Revoke("org_acme", "user_maya")
		_, err = h.issue(maya)
		unauthenticated(t, err, "revoked")
		if _, err := wiki.do(ctx, held.GetToken(), "publish", "handbook"); err != nil {
			t.Fatalf("Alex's capability after Maya's revocation: %v", err)
		}
		if _, err := h.issue(alex); err != nil {
			t.Fatalf("Alex's token after Maya's revocation: %v", err)
		}
	})
	t.Run("a sign-in check that cannot answer refuses the call and ends nothing", func(t *testing.T) {
		h := newPlatformHost(t, true)
		token := h.mint(t, "org_acme", "maya")
		if _, err := h.issue(token); err != nil {
			t.Fatal(err)
		}
		h.issuer.Down(true)
		_, err := h.issue(token)
		unauthenticated(t, err, "could not be read")
		h.issuer.Down(false)
		if _, err := h.issue(token); err != nil {
			t.Fatal(fmt.Errorf("once the check answers again: %w", err))
		}
	})
}
