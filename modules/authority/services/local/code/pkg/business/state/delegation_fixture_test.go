package state_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"gateway/pkg/business/testkit"
)

func TestDelegationFixtureRetainsExactIDsAndRefusesRoleMatchers(t *testing.T) {
	for _, selection := range []string{
		"resource_ids: [a]",
		"resources: [{id: a}]",
		"resources: [{prefix: a}]",
		"resources: []",
		"<<: {resources: [{id: a}]}",
	} {
		t.Run(selection, func(t *testing.T) {
			k := testkit.New(t)
			fixture := "delegations:\n  - id: narrow\n    organization: acme\n    grantor: remi\n    module: org-directory\n    scopes:\n      - kind: documents\n        actions: [write]\n        " + selection + "\n"
			err := k.State.LoadFixture(context.Background(), []byte(fixture))
			if !strings.HasPrefix(selection, "resource_ids:") {
				if err == nil || !strings.Contains(err.Error(), "resource_ids") {
					t.Fatalf("unsupported matcher syntax must refuse rather than widen: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			d, err := k.State.DelegationByID("narrow")
			if err != nil {
				t.Fatal(err)
			}
			scopes := d.WorkScopes()
			if len(scopes) != 1 || !slices.Equal(scopes[0].GetResourceIds(), []string{"a"}) {
				t.Fatalf("fixture restriction lost: %v", scopes)
			}
		})
	}
}
