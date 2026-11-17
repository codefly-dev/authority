package conformance

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// OrganisationRolesCase proves that organisation roles decide administration
// only: a person reaches a module only through a role (admin, user) on an
// installation, a solution's or a module page's. A host that lets an
// organisation role reach a module fails here.
//
//   - Administrator signs in an administrator of Fixture.Organization who
//     holds no role on any installation. It must administer (the suite lists
//     the organisation's installations with it) and must be refused at every
//     audience below.
//   - RoleGated are composed audiences whose roles decide (a solution, a
//     module page declaring roles), installed at the organisation: the
//     administrator holds no role on any of them. Fixture.Audience is always
//     among those asked.
//   - NoRoles are composed modules declaring no roles, installed at the
//     organisation: nobody's own session holds anything there, the
//     administrator's and Fixture.ViewerToken's included, whatever is asked.
//   - Kinds are, by audience of NoRoles, one kind and action the module
//     serves: an explicit ask is refused as an empty one is.
type OrganisationRolesCase struct {
	Administrator string
	RoleGated     []string
	NoRoles       []string
	Kinds         map[string]Expectation
}

func (c *client) organisationRoles(t *testing.T, ctx context.Context, f Fixture) {
	c.run(t, f, "an organisation role decides administration only: an administrator with no role on an installation is refused at every module, and nobody's own session holds anything at a module that declares no roles", func(t *testing.T, c *client, f Fixture) {
		o := f.OrganisationRoles
		if o == nil || o.Administrator == "" || len(o.NoRoles) == 0 {
			t.Fatal("required conformance fixture missing: an organisation administrator holding no installation role, and a composed module declaring no roles (OrganisationRoles)")
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": o.Administrator})
		// The administrator administers: the organisation's installations are
		// theirs to read.
		c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization})

		issue := func(session protoreflect.Message, audience string, ask *Expectation) error {
			request := map[string]any{"person": map[string]any{}, "audience": audience}
			if ask != nil {
				request["scopes"] = []any{map[string]any{"resource_kind": ask.Kind, "actions": []any{ask.Action}}}
			}
			_, err := c.call(as(ctx, session), "host.authority.v1.AuthorityService", "Issue", request)
			return err
		}
		for _, audience := range append([]string{f.Audience}, o.RoleGated...) {
			refused(t, issue(admin, audience, nil), codes.PermissionDenied, "holds no role on")
		}
		viewer := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		for _, audience := range o.NoRoles {
			for who, session := range map[string]protoreflect.Message{"the administrator": admin, "a person holding an installation role elsewhere": viewer} {
				err := issue(session, audience, nil)
				refused(t, err, codes.PermissionDenied, "declares no roles")
				if ask, named := o.Kinds[audience]; named {
					err = issue(session, audience, &ask)
					refused(t, err, codes.PermissionDenied, "declares no roles")
				}
				if err == nil {
					t.Fatalf("%s was issued a capability at %s, which declares no roles", who, audience)
				}
			}
		}
	})
}
