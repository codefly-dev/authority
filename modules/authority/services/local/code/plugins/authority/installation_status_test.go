package authority_test

import (
	"context"
	"errors"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	"gateway/plugins/authority"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestPersonIssueDistinguishesInstallationAndEntitlement(t *testing.T) {
	for _, tc := range []struct {
		state, person string
		want          codes.Code
	}{
		{"absent", "alex", codes.FailedPrecondition},
		{"pending", "alex", codes.FailedPrecondition},
		{"revoked", "alex", codes.FailedPrecondition},
		{"active", "maya", codes.PermissionDenied},
		{"active", "alex", codes.OK},
	} {
		t.Run(tc.state+"/"+tc.person, func(t *testing.T) {
			k := testkit.New(t)
			m := testkit.Wiki(1)
			m.Name, m.Principal = "new-solution", "new-solution"
			if _, err := k.State.ApplyManifest(m); err != nil {
				t.Fatal(err)
			}
			if tc.state == "pending" {
				k.State.OnInstall(func(context.Context, state.Installation) error { return errors.New("install not acknowledged") })
			}
			if tc.state != "absent" {
				inst, err := k.State.Install(t.Context(), "acme", m.Name, "viewer", "alex")
				if tc.state != "pending" && err != nil {
					t.Fatal(err)
				}
				if tc.state == "pending" && inst.Status != state.Pending {
					t.Fatal("fixture is not pending")
				}
				if tc.state == "revoked" {
					if err := k.State.Uninstall(inst.ID); err != nil {
						t.Fatal(err)
					}
				}
				// Installing grants nobody a role, the installer included:
				// alex is granted one, maya is not.
				if tc.state == "active" && tc.person == "alex" {
					if err := k.State.GrantRole(domain.RoleGrant{InstallationID: inst.ID, Role: "viewer", PersonID: "alex"}); err != nil {
						t.Fatal(err)
					}
				}
			}
			sess, err := k.State.SignIn("fixture-" + tc.person)
			if err != nil {
				t.Fatal(err)
			}
			ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+sess.ID))
			p := &authority.Plugin{Issuer: k.Issuer}
			_, err = p.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: m.Principal})
			if status.Code(err) != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}
