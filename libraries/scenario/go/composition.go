// Package scenario runs permission scenarios against a composition: real
// services, started by Codefly from a plain `go test`, behind the real local
// authority on its fixture. A test acts as a fixture person by name and calls
// what a page calls, through the authority's edge and hop, so every verdict
// and every result is the composition's own: the authority's issuance, the
// hop's admission of the method, the module's handler and each onward hop it
// makes in turn. Nothing here decides, and nothing stands in for a module or
// for the authority.
//
// A composition is one anchor service: a service that never runs, whose
// dependencies are what the run starts (the SDK's dependency stack, with the
// test process standing where the anchor would). The anchor depends on the
// authority's edge (http) and on the local authority (grpc), and on whatever
// the scenarios call. Start one per test package, in TestMain, and share it:
//
//	func TestMain(m *testing.M) { os.Exit(scenario.Main(m, &wiki, scenario.Options{Anchor: "…/services/scenarios"})) }
//
//	func TestTraces(t *testing.T) {
//		wiki.Check(t, scenario.Row{Name: "read the traces", Page: "wiki",
//			Procedure: "tracing.v1.TraceReadService/ListTraces",
//			Want: scenario.Want{"dana": scenario.Allow, "bob": scenario.Deny("holds no role on wiki")}})
//	}
//
// What it cannot see: a host other than the local authority (the fixture's
// people and the sign-in by fixture token are its own), and anything outside
// the composition, which a scenario stubs where the module that calls it lets
// a composition configure a stand-in.
package scenario

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"github.com/codefly-dev/core/sdk"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Options is what a test package says of its composition.
type Options struct {
	// Anchor is the anchor service's directory, absolute or relative to the
	// test's working directory.
	Anchor string
	// Scope is the naming scope's prefix; the session adds its own identity,
	// so two packages or two checkouts never share a run. Empty is "scenario".
	Scope string
	// Timeout bounds each phase of the start. Empty is ten minutes: a first
	// start builds every service.
	Timeout time.Duration
	// Without are dependencies ("<module>/<service>") the run leaves out, and
	// WithoutConfigurations the workspace configuration groups that name them.
	Without, WithoutConfigurations []string
	// Roots are services ("<module>/<service>") the run starts as roots
	// beside the anchor's dependencies: what the scenarios need running and
	// nothing they call depends on, a worker that polls a store or a
	// dispatcher that progresses it. The anchor names what the scenarios
	// call; a service private to its module is never one of those, and is
	// named here as `codefly run service` names it on a command line. A root
	// hands the scenarios no address.
	Roots []string
	// Set are workspace configuration values of this run alone.
	Set []Value
	// Install are solutions the organisation's administrator installs before
	// the first scenario, each with the consent the authority reviews for it.
	// A target already installed is left as it is.
	Install []string
	// Seated are the targets the fixture's people keep their roles on. The
	// fixture seats its people on every role-gated target a run composes; a
	// person who holds a product's role in a real organisation holds nothing
	// on the pages of the modules behind it, and a blanket seat there hides a
	// refusal the product's own role should have met. When Seated names any
	// target, the administrator withdraws every role granted on every other
	// installation of their organisation before the first scenario, and the
	// seating holds for the whole run: the host seats its people again on
	// every installation after each install and each delivery (a module
	// starting late, a hot reload), so the harness looks again after every
	// install it makes and before every call a person makes, and withdraws
	// what came back, saying so on stderr. A role a scenario grants itself
	// (Grant) is its own and is kept.
	//
	// Empty leaves the fixture as it is: its people hold their roles on every
	// role-gated target, the pages of the modules behind a product included.
	// A call a person makes at such a module on their own session or from the
	// module's own page is then answered on that seat, whatever the product's
	// role reaches, and their session lists every such page; so a run with no
	// Seated does not show that a module is reached through the product's
	// role alone, and a refusal that depends on it never appears.
	Seated []string
	// Administrator installs and withdraws: a fixture person who administers their
	// organisation. When omitted, it is the one administrator of the
	// composition's own organisation, the one the fixture lists first (Acme,
	// on the local authority's fixture); another organisation's administrator
	// (Outsider) is never chosen for it.
	Administrator string
}

// Value is one workspace configuration value: group Name, Key, Value.
type Value struct{ Name, Key, Value string }

// Composition is a started composition and the fixture people signed in to it.
type Composition struct {
	deps    *sdk.Dependencies
	anchor  string
	conn    *grpc.ClientConn
	origin  string
	client  *http.Client
	started time.Duration

	mu     sync.Mutex
	people map[string]*sessionv1.FixturePerson
	signed map[string]*Person
	// home is the composition's own organisation: the administrator's, or
	// the one the fixture lists first. Outsider is held against it.
	home string

	// seating is the seating the run asked for (Options.Seated), held before
	// every call; nil when it asked for none.
	seating *seating
}

// seating is the targets the fixture's people keep their roles on, and what
// holding it takes.
type seating struct {
	mu            sync.Mutex
	administrator string
	seated        []string
	// bearer is the administrator's session at the host, opened once.
	bearer string
	// own are the roles a scenario granted itself (Grant), which are kept.
	own map[roleGranted]bool
	// held: the seating was established once; a role withdrawn after that is
	// one the host granted again.
	held bool
}

// roleGranted is one role a scenario granted a person on a target.
type roleGranted struct{ organization, target, role, person string }

// Main runs a package's tests on one composition: it starts it, points
// *composition at it, runs m and tears the run down. A start that fails is
// reported with its reason and fails the package.
func Main(m *testing.M, composition **Composition, options Options) int {
	c, err := Start(context.Background(), options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scenario: the composition did not start:", err)
		return 1
	}
	*composition = c
	fmt.Fprintf(os.Stderr, "scenario: the composition started in %s\n", c.started.Round(time.Second))
	defer c.Close()
	return m.Run()
}

// Start starts the anchor's dependencies and signs nobody in yet.
func Start(ctx context.Context, options Options) (*Composition, error) {
	anchor, err := filepath.Abs(options.Anchor)
	if err != nil {
		return nil, err
	}
	scope, timeout := options.Scope, options.Timeout
	if scope == "" {
		scope = "scenario"
	}
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	began := time.Now()
	deps, err := sdk.WithDependencies(ctx, sessionOptions(anchor, scope, timeout, options)...)
	if err != nil {
		return nil, err
	}
	c := &Composition{deps: deps, anchor: anchor, client: &http.Client{Timeout: 2 * time.Minute, Transport: host.HTTPTransport()}, signed: map[string]*Person{}, started: time.Since(began)}
	if err := c.connect(ctx, options); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// sessionOptions is what the options say of the dependency session: the
// anchor, the naming scope, what the run leaves out, the roots it starts
// beside the anchor's dependencies and the values of this run alone.
func sessionOptions(anchor, scope string, timeout time.Duration, options Options) []sdk.OptionFunc {
	opts := []sdk.OptionFunc{sdk.WithDirectory(anchor), sdk.WithNamingScope(scope), sdk.WithTimeout(timeout),
		sdk.WithCommandScopedEnvironment(),
		sdk.WithExcludedDependencies(options.Without...), sdk.WithExcludedWorkspaceConfigurations(options.WithoutConfigurations...)}
	if len(options.Roots) > 0 {
		opts = append(opts, sdk.WithCoRoots(options.Roots...))
	}
	for _, v := range options.Set {
		opts = append(opts, sdk.WithWorkspaceConfiguration(v.Name, v.Key, v.Value))
	}
	return opts
}

// Close stops the run and removes what it created.
func (c *Composition) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = c.deps.Destroy(ctx)
}

// Started is how long the composition took to start.
func (c *Composition) Started() time.Duration { return c.started }

// connect resolves the edge and the host from what the run delivered to the
// anchor, reads the fixture's people from the host and installs what the
// options name.
func (c *Composition) connect(ctx context.Context, options Options) error {
	edge, err := c.address("authority", "edge", "http")
	if err != nil {
		return err
	}
	address, err := c.address("authority", "local", "grpc")
	if err != nil {
		return err
	}
	c.origin = "http://" + edge
	if c.conn, err = grpc.NewClient(address, host.DialOptions(insecure.NewCredentials())...); err != nil {
		return err
	}
	listed, err := sessionv1.NewSessionServiceClient(c.conn).ListFixturePeople(ctx, &sessionv1.ListFixturePeopleRequest{})
	if err != nil {
		return fmt.Errorf("the host lists no fixture people: %w", err)
	}
	c.people = map[string]*sessionv1.FixturePerson{}
	for _, p := range listed.GetPeople() {
		c.people[p.GetPersonId()] = p
	}
	administrator, err := fixtureAdministrator(options, listed.GetPeople())
	if err != nil {
		return err
	}
	c.home = homeOrganization(administrator, listed.GetPeople())
	for _, target := range options.Install {
		if err := c.install(ctx, administrator, target); err != nil {
			return fmt.Errorf("install %s as %s: %w", target, administrator, err)
		}
	}
	return c.seat(ctx, options, administrator)
}

// fixtureAdministrator is who installs and withdraws: the one the options
// name, or the one administrator of the composition's own organisation, the
// one the fixture lists first. A fixture with a second organisation (the
// outsider's) still names one administrator for setup.
func fixtureAdministrator(options Options, people []*sessionv1.FixturePerson) (string, error) {
	if options.Administrator != "" || (len(options.Install) == 0 && len(options.Seated) == 0) {
		return options.Administrator, nil
	}
	home := homeOrganization("", people)
	var admins []string
	for _, person := range people {
		if person.GetOrganizationId() == home && slices.Contains(person.GetRoles(), "admin") {
			admins = append(admins, person.GetPersonId())
		}
	}
	if len(admins) != 1 {
		return "", fmt.Errorf("fixture lists %d administrators of its first organization %q; specify Options.Administrator", len(admins), home)
	}
	return admins[0], nil
}

// homeOrganization is the composition's own organisation: administrator's,
// when the fixture lists them, or the one of the first person it lists.
func homeOrganization(administrator string, people []*sessionv1.FixturePerson) string {
	for _, person := range people {
		if person.GetPersonId() == administrator {
			return person.GetOrganizationId()
		}
	}
	if len(people) == 0 {
		return ""
	}
	return people[0].GetOrganizationId()
}

// seat keeps the fixture's people on options.Seated alone, when it names any
// target, from here to the end of the run.
func (c *Composition) seat(ctx context.Context, options Options, administrator string) error {
	if len(options.Seated) == 0 {
		return nil
	}
	c.seating = &seating{administrator: administrator, seated: options.Seated, own: map[roleGranted]bool{}}
	return c.holdSeats(ctx)
}

// holdSeats holds the seating the run asked for: whatever role stands on an
// installation that is not seated is withdrawn, the first time and every
// time the host granted it again since (it seats its people on every
// installation after each install and each delivery).
func (c *Composition) holdSeats(ctx context.Context) error {
	s := c.seating
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	withdrawn, err := c.seatOnly(ctx, s)
	if status.Code(err) == codes.Unauthenticated && len(withdrawn) == 0 {
		// The administrator's session ended: open another, once.
		s.bearer = ""
		withdrawn, err = c.seatOnly(ctx, s)
	}
	if err != nil {
		return fmt.Errorf("seat the fixture's people on %v alone, as %s: %w", s.seated, s.administrator, err)
	}
	if s.held && len(withdrawn) > 0 {
		fmt.Fprintf(os.Stderr, "scenario: the host seated its people again on %v (an install or a delivery); withdrawn again, as Seated asks\n", withdrawn)
	}
	s.held = true
	return nil
}

// administer is ctx carrying the administrator's own session at the host,
// and their organisation.
func (c *Composition) administer(ctx context.Context, administrator string) (context.Context, *sessionv1.FixturePerson, error) {
	person, ok := c.people[administrator]
	if !ok {
		return nil, nil, fmt.Errorf("%s is not a fixture person", administrator)
	}
	session, err := sessionv1.NewSessionServiceClient(c.conn).SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: person.GetFixtureToken()})
	if err != nil {
		return nil, nil, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+session.GetBearer()), person, nil
}

// seatOnly withdraws every role granted on every installation of the
// administrator's organisation whose target is not seated, but those a
// scenario granted itself, and answers the targets it withdrew a role on.
func (c *Composition) seatOnly(ctx context.Context, s *seating) ([]string, error) {
	person, ok := c.people[s.administrator]
	if !ok {
		return nil, fmt.Errorf("%s is not a fixture person", s.administrator)
	}
	if s.bearer == "" {
		session, err := sessionv1.NewSessionServiceClient(c.conn).SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: person.GetFixtureToken()})
		if err != nil {
			return nil, err
		}
		s.bearer = session.GetBearer()
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.bearer)
	org := person.GetOrganizationId()
	installations := installationv1.NewInstallationServiceClient(c.conn)
	listed, err := installations.List(ctx, &installationv1.ListRequest{OrganizationId: org})
	if err != nil {
		return nil, err
	}
	var withdrawn []string
	for _, installation := range listed.GetInstallations() {
		if slices.Contains(s.seated, installation.GetTarget()) {
			continue
		}
		grants, err := installations.ListRoleGrants(ctx, &installationv1.ListRoleGrantsRequest{OrganizationId: org, InstallationId: installation.GetId()})
		if err != nil {
			return withdrawn, fmt.Errorf("the roles granted on %s: %w", installation.GetTarget(), err)
		}
		for _, grant := range grants.GetGrants() {
			if grant.GetTeamId() == "" && s.own[roleGranted{org, installation.GetTarget(), grant.GetRole(), grant.GetPersonId()}] {
				continue
			}
			if _, err := installations.RevokeRole(ctx, &installationv1.RevokeRoleRequest{OrganizationId: org, InstallationId: installation.GetId(),
				Role: grant.GetRole(), PersonId: grant.GetPersonId(), TeamId: grant.GetTeamId()}); err != nil {
				return withdrawn, fmt.Errorf("withdraw %s on %s from %s%s: %w", grant.GetRole(), installation.GetTarget(), grant.GetPersonId(), grant.GetTeamId(), err)
			}
			if !slices.Contains(withdrawn, installation.GetTarget()) {
				withdrawn = append(withdrawn, installation.GetTarget())
			}
		}
	}
	return withdrawn, nil
}

// address is the address the run delivered to the anchor for a dependency's
// endpoint; the anchor declares the dependency, so the run resolves it.
func (c *Composition) address(module, service, endpoint string) (string, error) {
	prefix := "CODEFLY__ENDPOINT__" + key(module) + "__" + key(service) + "__" + key(endpoint) + "__"
	for name, value := range c.deps.EnvironmentVariables() {
		if strings.HasPrefix(name, prefix) && value != "" {
			return strings.TrimPrefix(strings.TrimPrefix(value, "http://"), "https://"), nil
		}
	}
	return "", fmt.Errorf("the run delivered no address of %s/%s/%s: the anchor must depend on it", module, service, endpoint)
}

func key(name string) string { return strings.ToUpper(strings.ReplaceAll(name, "-", "_")) }

// install installs target for the administrator's organisation with the
// consent the authority reviews, unless it is installed already.
func (c *Composition) install(ctx context.Context, administrator, target string) error {
	ctx, person, err := c.administer(ctx, administrator)
	if err != nil {
		return err
	}
	org := person.GetOrganizationId()
	review, err := installationv1.NewOfferServiceClient(c.conn).ReviewOffer(ctx, &installationv1.ReviewRequest{OrganizationId: org, Target: target})
	if err != nil {
		return err
	}
	if review.GetInstallation().GetStatus() == installationv1.Installation_STATUS_ACTIVE {
		return nil
	}
	approval := review.GetApproval()
	if approval.GetOperationId() == "" {
		approval.OperationId = uuid.NewString()
	}
	// No role is named: the installation's own agent holds what the
	// solution's signed declaration says (installation_role).
	installed, err := installationv1.NewInstallationServiceClient(c.conn).Install(ctx, &installationv1.InstallRequest{
		OrganizationId: org, Target: target, OwnerPersonId: person.GetPersonId(), Approval: approval})
	if err != nil {
		return err
	}
	if installed.GetStatus() != installationv1.Installation_STATUS_ACTIVE {
		return fmt.Errorf("the installation is %s, not active", installed.GetStatus())
	}
	return nil
}

// Origin is the edge's origin, for a scenario that drives something other
// than a call (a browser, a tool) against the same composition.
func (c *Composition) Origin() string { return c.origin }

// Install installs target for the organisation administrator administers,
// with the consent the authority reviews: a scenario's own installation, in an
// organisation no other scenario touches, so what it reads is what it wrote.
// The host seats its people again on every installation after an install;
// the seating the run asked for (Options.Seated) is held again here.
func (c *Composition) Install(t testing.TB, administrator, target string) {
	t.Helper()
	if err := c.install(context.Background(), administrator, target); err != nil {
		t.Fatalf("install %s as %s: %v", target, administrator, err)
	}
	if err := c.holdSeats(context.Background()); err != nil {
		t.Fatalf("after installing %s: %v", target, err)
	}
}

// Grant grants role on target's installation to person, as administrator. On
// a target the run does not seat (Options.Seated), the grant is the
// scenario's own and is kept.
func (c *Composition) Grant(t testing.TB, administrator, target, role, person string) {
	t.Helper()
	ctx, admin, err := c.administer(context.Background(), administrator)
	if err != nil {
		t.Fatal(err)
	}
	installations := installationv1.NewInstallationServiceClient(c.conn)
	listed, err := installations.List(ctx, &installationv1.ListRequest{OrganizationId: admin.GetOrganizationId()})
	if err != nil {
		t.Fatal(err)
	}
	for _, installation := range listed.GetInstallations() {
		if installation.GetTarget() != target {
			continue
		}
		if _, err := installations.GrantRole(ctx, &installationv1.GrantRoleRequest{OrganizationId: admin.GetOrganizationId(),
			InstallationId: installation.GetId(), Role: role, PersonId: person}); err != nil {
			t.Fatalf("grant %s on %s to %s as %s: %v", role, target, person, administrator, err)
		}
		if s := c.seating; s != nil {
			s.mu.Lock()
			s.own[roleGranted{admin.GetOrganizationId(), target, role, person}] = true
			s.mu.Unlock()
		}
		return
	}
	t.Fatalf("%s is not installed for %s", target, admin.GetOrganizationId())
}
