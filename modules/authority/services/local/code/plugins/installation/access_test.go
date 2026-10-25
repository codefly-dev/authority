package installation_test

import (
	"context"
	"testing"

	"gateway/pkg/business/testkit"
	installationv1 "gateway/pkg/gen/host/installation/v1"
	"gateway/plugins/installation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestInstallationAdministrationUsesCurrentCallerAndOrganization(t *testing.T) {
	k := testkit.New(t)
	p := &installation.Plugin{State: k.State}
	for _, tc := range []struct {
		name, token, org string
		want             codes.Code
	}{
		{"anonymous", "", "acme", codes.Unauthenticated},
		{"forged", "not-a-session", "acme", codes.Unauthenticated},
		{"viewer", "fixture-maya", "acme", codes.PermissionDenied},
		{"foreign admin", "fixture-zoe", "acme", codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bearer := tc.token
			if sess, err := k.State.SignIn(tc.token); err == nil {
				bearer = sess.ID
			}
			ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+bearer))
			for name, call := range map[string]func() error{
				"list": func() error { _, err := p.List(ctx, &installationv1.ListRequest{OrganizationId: tc.org}); return err },
				"install": func() error {
					_, err := p.Install(ctx, &installationv1.InstallRequest{OrganizationId: tc.org})
					return err
				},
				"grant": func() error {
					_, err := p.GrantToTeam(ctx, &installationv1.GrantToTeamRequest{OrganizationId: tc.org})
					return err
				},
			} {
				if err := call(); status.Code(err) != tc.want {
					t.Errorf("%s: want %s, got %v", name, tc.want, err)
				}
			}
		})
	}
	sess, err := k.State.SignIn("fixture-alex")
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+sess.ID))
	if _, err := p.List(ctx, &installationv1.ListRequest{OrganizationId: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := k.State.LoadFixture(t.Context(), []byte("people:\n  - id: alex\n    organization: acme\n    fixture_token: fixture-alex\n    roles: []\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.List(ctx, &installationv1.ListRequest{OrganizationId: "acme"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("removed admin role remains usable with its old session: %v", err)
	}
}

func TestOrganizationOwnerCanReadInstallations(t *testing.T) {
	k := testkit.New(t)
	if err := k.State.LoadFixture(t.Context(), []byte(`roles:
  - organization: acme
    name: owner
    scopes: []
people:
  - id: owner
    organization: acme
    fixture_token: fixture-owner
    roles: [owner]
`)); err != nil {
		t.Fatal(err)
	}
	sess, err := k.State.SignIn("fixture-owner")
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+sess.ID))
	p := &installation.Plugin{State: k.State}
	if _, err := p.List(ctx, &installationv1.ListRequest{OrganizationId: "acme"}); err != nil {
		t.Fatal(err)
	}
}
