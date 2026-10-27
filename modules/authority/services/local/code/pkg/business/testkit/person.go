package testkit

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"gateway/pkg/business/issuer"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// PersonIssue is what person is issued at audience asking for scopes, or
// everything they hold there when none, through the wire: signed in by their
// fixture token.
func (k *Kit) PersonIssue(t *testing.T, person, audience string, scopes ...*authorityv1.WorkScopeV1) (*authorityv1.IssueResponse, error) {
	t.Helper()
	token := ""
	for _, p := range k.State.FixturePeople() {
		if p.ID == person {
			token = p.FixtureToken
		}
	}
	sess, err := k.State.SignIn(token)
	if err != nil {
		t.Fatalf("sign in %s: %v", person, err)
	}
	return k.Issuer.Issue(issuer.WithSession(context.Background(), sess.ID), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: audience, Scopes: scopes})
}

// PersonScopes is what person holds at audience now: the effective scopes of
// what they are issued, none when they hold nothing there.
func (k *Kit) PersonScopes(t *testing.T, person, audience string) ([]*basev0.WorkScopeV1, error) {
	t.Helper()
	out, err := k.PersonIssue(t, person, audience)
	if err != nil {
		return nil, err
	}
	chain := out.GetContext().GetActorChain()
	scopes := out.GetContext().GetAuthorityScopes()
	if len(chain) > 0 {
		scopes = chain[len(chain)-1].GetGrantedScopes()
	}
	return issuer.FromWire(scopes), nil
}

// ResourceGrants is which resources of kind person may act on with action at
// audience, as the authority answers it for their capability: one asking for
// action on ids when it names any, else for everything they hold.
func (k *Kit) ResourceGrants(t *testing.T, person, audience, kind, action string, ids ...string) ([]authority.Grant, error) {
	t.Helper()
	var ask []*authorityv1.WorkScopeV1
	if len(ids) > 0 {
		ask = append(ask, &authorityv1.WorkScopeV1{ResourceKind: kind, Actions: []string{action}, ResourceIds: ids})
	}
	out, err := k.PersonIssue(t, person, audience, ask...)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errors.New("nothing issued")
	}
	return k.Issuer.ListResources(context.Background(), out.GetToken(), audience, kind, action)
}

// Teams are the teams granted a role on installation id, sorted, as its
// organisation's administrator lists them.
func (k *Kit) Teams(t *testing.T, id string) []string {
	t.Helper()
	inst, ok := k.State.Installation(id)
	if !ok {
		return nil
	}
	admin := authority.Person{ID: "alex", Organization: "acme"}
	if inst.Organization == "globex" {
		admin = authority.Person{ID: "zoe", Organization: "globex"}
	}
	grants, err := k.State.Service().ListRoleGrants(context.Background(), admin, inst.Organization, id)
	if err != nil {
		return nil
	}
	var teams []string
	for _, g := range grants {
		if g.TeamID != "" {
			teams = append(teams, g.TeamID)
		}
	}
	slices.Sort(teams)
	return teams
}

// Revision is org's current authorization revision.
func (k *Kit) Revision(t *testing.T, org string) uint64 {
	t.Helper()
	revision, err := k.State.Service().Revisions().AuthorizationRevision(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}
