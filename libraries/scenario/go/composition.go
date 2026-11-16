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
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/codefly-dev/core/sdk"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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
	// Set are workspace configuration values of this run alone.
	Set []Value
	// Generate are Codefly commands run in the composition's workspace before
	// the start, each given the run's naming scope (--naming-scope): what the
	// composition generates per scope, as its own run line does
	// ({"generate", "runnable-bindings", "--env", "local"}).
	Generate [][]string
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
	// installation before the first scenario. Empty leaves the fixture as it
	// is.
	Seated []string
	// Administrator installs and withdraws: a fixture person who administers their
	// organisation. Empty is "alice".
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
}

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
	// Named ports: a hop names its upstreams and an upstream names the hop, a
	// cycle no ephemeral port can be told into.
	opts := []sdk.OptionFunc{sdk.WithDirectory(anchor), sdk.WithNamingScope(scope), sdk.WithTimeout(timeout),
		sdk.WithCommandScopedEnvironment(), sdk.WithNamedPorts(),
		sdk.WithExcludedDependencies(options.Without...), sdk.WithExcludedWorkspaceConfigurations(options.WithoutConfigurations...)}
	for _, v := range options.Set {
		opts = append(opts, sdk.WithWorkspaceConfiguration(v.Name, v.Key, v.Value))
	}
	for _, command := range options.Generate {
		opts = append(opts, sdk.WithPrepare(func(ctx context.Context, dir, scope string) error {
			generate := exec.CommandContext(ctx, codefly(), append(slices.Clone(command), "--naming-scope", scope)...)
			generate.Dir = dir
			if out, err := generate.CombinedOutput(); err != nil {
				return fmt.Errorf("codefly %s: %w: %s", strings.Join(command, " "), err, out)
			}
			return nil
		}))
	}
	began := time.Now()
	deps, err := sdk.WithDependencies(ctx, opts...)
	if err != nil {
		return nil, err
	}
	c := &Composition{deps: deps, anchor: anchor, client: &http.Client{Timeout: 2 * time.Minute}, signed: map[string]*Person{}, started: time.Since(began)}
	if err := c.connect(ctx, options); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
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
	host, err := c.address("authority", "local", "grpc")
	if err != nil {
		return err
	}
	c.origin = "http://" + edge
	if c.conn, err = grpc.NewClient(host, grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
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
	administrator := options.Administrator
	if administrator == "" {
		administrator = "alice"
	}
	for _, target := range options.Install {
		if err := c.install(ctx, administrator, target); err != nil {
			return fmt.Errorf("install %s as %s: %w", target, administrator, err)
		}
	}
	if len(options.Seated) > 0 {
		if err := c.seatOnly(ctx, administrator, options.Seated); err != nil {
			return fmt.Errorf("seat the fixture's people on %v alone, as %s: %w", options.Seated, administrator, err)
		}
	}
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
// administrator's organisation whose target is not one of seated.
func (c *Composition) seatOnly(ctx context.Context, administrator string, seated []string) error {
	ctx, person, err := c.administer(ctx, administrator)
	if err != nil {
		return err
	}
	org := person.GetOrganizationId()
	installations := installationv1.NewInstallationServiceClient(c.conn)
	listed, err := installations.List(ctx, &installationv1.ListRequest{OrganizationId: org})
	if err != nil {
		return err
	}
	for _, installation := range listed.GetInstallations() {
		if slices.Contains(seated, installation.GetTarget()) {
			continue
		}
		grants, err := installations.ListRoleGrants(ctx, &installationv1.ListRoleGrantsRequest{OrganizationId: org, InstallationId: installation.GetId()})
		if err != nil {
			return fmt.Errorf("the roles granted on %s: %w", installation.GetTarget(), err)
		}
		for _, grant := range grants.GetGrants() {
			if _, err := installations.RevokeRole(ctx, &installationv1.RevokeRoleRequest{OrganizationId: org, InstallationId: installation.GetId(),
				Role: grant.GetRole(), PersonId: grant.GetPersonId(), TeamId: grant.GetTeamId()}); err != nil {
				return fmt.Errorf("withdraw %s on %s from %s%s: %w", grant.GetRole(), installation.GetTarget(), grant.GetPersonId(), grant.GetTeamId(), err)
			}
		}
	}
	return nil
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

// codefly is the binary the dependency stack itself runs: CODEFLY_BINARY, or
// the one on PATH.
func codefly() string {
	if binary := strings.TrimSpace(os.Getenv("CODEFLY_BINARY")); binary != "" {
		return binary
	}
	return "codefly"
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
