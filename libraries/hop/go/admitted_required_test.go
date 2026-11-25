package hop_test

import (
	"fmt"
	"slices"
	"testing"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

// A method that requires more than one permission: a row write requires
// reading and writing records, a typed read requires a record and its type,
// and a content write requires reading and carries writing content.
var (
	readsAndWrites = policy.Method{Requires: []policy.Permission{policy.Of("records.records", "read"), policy.Of("records.records", "write")}}
	recordAndType  = policy.Method{Requires: []policy.Permission{policy.Of("records.records", "read"), policy.Of("records.types", "read")}}
	carriesContent = policy.Method{Requires: []policy.Permission{policy.Of("records.records", "read")}, Carries: []policy.Permission{policy.Of("records.records", "write_content")}}
)

func holds(kind, action, owner string, ids ...string) hop.Grant {
	return hop.Grant{Kind: kind, Action: action, Owner: owner, Resources: ids}
}

// reach is a selection's answers in one comparable line.
func reach(s hop.Selection) string {
	return fmt.Sprintf("empty=%v whole=%v owners=%v named=%v", s.Empty(), s.Whole(), s.Owners(), s.Named())
}

const nothing = "empty=true whole=false owners=[] named=[]"

// Required is the intersection, across what the method requires, of where the
// call holds each permission: owner by owner and, for named resources, id by
// id. A grant that selects no owner holds its permission on every owner, so it
// reads as the whole kind there. RequiredOwnerSelected is the same
// intersection of the owner-selected grants alone: a grant that selects no
// owner lends nothing to a grant that selects one.
func TestRequiredIsWhereEveryRequiredPermissionIsHeld(t *testing.T) {
	const records, types = "records.records", "records.types"
	for _, c := range []struct {
		name          string
		declared      policy.Method
		grants        []hop.Grant
		required      string
		ownerSelected string
	}{
		{"two actions of one kind held on different owners", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "installation-b")},
			nothing, nothing},
		{"two actions of one kind held on the same owner", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "installation-a")},
			"empty=false whole=false owners=[installation-a] named=[]", "empty=false whole=false owners=[installation-a] named=[]"},
		{"one held on the whole kind, one on an owner", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "")},
			"empty=false whole=false owners=[installation-a] named=[]", nothing},
		{"one held on the whole kind and on the owner, one on that owner", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", ""), holds(records, "write", "installation-a")},
			"empty=false whole=false owners=[installation-a] named=[]", "empty=false whole=false owners=[installation-a] named=[]"},
		{"both held on the whole kind", readsAndWrites,
			[]hop.Grant{holds(records, "read", ""), holds(records, "write", "")},
			"empty=false whole=true owners=[] named=[]", nothing},
		{"one held on an owner, one on a resource named within that owner", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "installation-a", "r-1")},
			"empty=false whole=false owners=[] named=[{installation-a [r-1]}]", "empty=false whole=false owners=[] named=[{installation-a [r-1]}]"},
		{"one held on an owner, one on a resource named within another owner", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "installation-b", "r-1")},
			nothing, nothing},
		{"one held on an owner, one on a resource named with no owner", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "", "r-1")},
			"empty=false whole=false owners=[] named=[{installation-a [r-1]}]", nothing},
		{"named resources of one owner, held together on the ids both name", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a", "r-1", "r-2"), holds(records, "write", "installation-a", "r-2", "r-3")},
			"empty=false whole=false owners=[] named=[{installation-a [r-2]}]", "empty=false whole=false owners=[] named=[{installation-a [r-2]}]"},
		{"one held on nothing", readsAndWrites,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(types, "write", "installation-a")},
			nothing, nothing},
		{"one held on nothing, the other on the whole kind", readsAndWrites,
			[]hop.Grant{holds(records, "write", "")},
			nothing, nothing},
		{"every action on one owner, one action on another", readsAndWrites,
			[]hop.Grant{holds(records, policy.AnyAction, "installation-a"), holds(records, "read", "installation-b")},
			"empty=false whole=false owners=[installation-a] named=[]", "empty=false whole=false owners=[installation-a] named=[]"},
		{"two kinds held on different owners", recordAndType,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(types, "read", "installation-b")},
			nothing, nothing},
		{"two kinds, one on two owners and one on one of them", recordAndType,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "read", "installation-b"), holds(types, "read", "installation-b")},
			"empty=false whole=false owners=[installation-b] named=[]", "empty=false whole=false owners=[installation-b] named=[]"},
		{"two kinds, one on the whole kind and one on an owner", recordAndType,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(types, "read", "")},
			"empty=false whole=false owners=[installation-a] named=[]", nothing},
		{"two kinds, one held on nothing", recordAndType,
			[]hop.Grant{holds(records, "read", "installation-a"), holds(types, "define", "installation-a")},
			nothing, nothing},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := hop.AdmissionOf(c.declared, "/records.v1.Records/Write", c.grants)
			if got := reach(a.Required()); got != c.required {
				t.Errorf("Required reads\n  %s, want\n  %s", got, c.required)
			}
			if got := reach(a.RequiredOwnerSelected()); got != c.ownerSelected {
				t.Errorf("RequiredOwnerSelected reads\n  %s, want\n  %s", got, c.ownerSelected)
			}
			// The reading modules already write is the same one.
			if got := reach(a.Required().OwnerSelected()); got != c.ownerSelected {
				t.Errorf("Required().OwnerSelected() reads\n  %s, want\n  %s", got, c.ownerSelected)
			}
		})
	}
}

// Carried is how far what the method carries reaches, within what it
// requires; cut to owner-selected grants, neither side lends the other an
// owner it did not select.
func TestCarriedIsWithinRequiredAndAnUnselectedGrantLendsItNothing(t *testing.T) {
	const records = "records.records"
	for _, c := range []struct {
		name          string
		grants        []hop.Grant
		carried       string
		ownerSelected string
	}{
		{"required on two owners, carried on one",
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "read", "installation-b"), holds(records, "write_content", "installation-a")},
			"empty=false whole=false owners=[installation-a] named=[]", "empty=false whole=false owners=[installation-a] named=[]"},
		{"required on one owner, carried on another",
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write_content", "installation-b")},
			nothing, nothing},
		{"required on the whole kind, carried on an owner",
			[]hop.Grant{holds(records, "read", ""), holds(records, "write_content", "installation-a")},
			"empty=false whole=false owners=[installation-a] named=[]", nothing},
		{"required on an owner, carried on the whole kind",
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write_content", "")},
			"empty=false whole=false owners=[installation-a] named=[]", nothing},
		{"required on an owner, carried on a resource named within it",
			[]hop.Grant{holds(records, "read", "installation-a"), holds(records, "write_content", "installation-a", "r-1")},
			"empty=false whole=false owners=[] named=[{installation-a [r-1]}]", "empty=false whole=false owners=[] named=[{installation-a [r-1]}]"},
		{"carried where nothing required is held",
			[]hop.Grant{holds(records, "write_content", "installation-a")},
			nothing, nothing},
		{"only what is required is held",
			[]hop.Grant{holds(records, "read", "installation-a")},
			nothing, nothing},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := hop.AdmissionOf(carriesContent, "/records.v1.Records/WriteContent", c.grants)
			if got := reach(a.Carried()); got != c.carried {
				t.Errorf("Carried reads\n  %s, want\n  %s", got, c.carried)
			}
			if got := reach(a.CarriedOwnerSelected()); got != c.ownerSelected {
				t.Errorf("CarriedOwnerSelected reads\n  %s, want\n  %s", got, c.ownerSelected)
			}
			if got := reach(a.Carried().OwnerSelected()); got != c.ownerSelected {
				t.Errorf("Carried().OwnerSelected() reads\n  %s, want\n  %s", got, c.ownerSelected)
			}
		})
	}
}

// Every way two required permissions can each be held on up to two of a
// handful of selections: Required reaches a resource exactly when every
// required permission reaches it, and the owner-selected reading reaches it
// exactly when every required permission reaches it through a grant that
// selects an owner. Neither is ever wider than the permission-by-permission
// answer a module would compute by hand from Each.
func TestRequiredIsNeverWiderThanEachPermissionRead(t *testing.T) {
	const records = "records.records"
	terms := [][2]any{
		{"", []string(nil)}, {"installation-a", []string(nil)}, {"installation-b", []string(nil)},
		{"installation-a", []string{"r-1", "r-2"}}, {"installation-a", []string{"r-2"}}, {"installation-b", []string{"r-1"}}, {"", []string{"r-1", "r-3"}},
	}
	var choices [][]int
	choices = append(choices, nil)
	for i := range terms {
		choices = append(choices, []int{i})
		for j := i + 1; j < len(terms); j++ {
			choices = append(choices, []int{i, j})
		}
	}
	owners, ids := []string{"installation-a", "installation-b", "installation-c"}, []string{"", "r-1", "r-2", "r-3", "r-4"}
	for _, reads := range choices {
		for _, writes := range choices {
			var grants []hop.Grant
			for _, i := range reads {
				grants = append(grants, holds(records, "read", terms[i][0].(string), terms[i][1].([]string)...))
			}
			for _, i := range writes {
				grants = append(grants, holds(records, "write", terms[i][0].(string), terms[i][1].([]string)...))
			}
			a := hop.AdmissionOf(readsAndWrites, "/records.v1.Records/Write", grants)
			each := a.Each()
			if len(each) != 2 {
				t.Fatalf("two required permissions read as %d", len(each))
			}
			required, selected := a.Required(), a.RequiredOwnerSelected()
			wantWhole := each[0].Selection.Whole() && each[1].Selection.Whole()
			if required.Whole() != wantWhole || selected.Whole() {
				t.Fatalf("%+v: whole reads %v (owner-selected %v), want %v (never)", grants, required.Whole(), selected.Whole(), wantWhole)
			}
			var wantOwners, wantSelectedOwners []string
			for _, owner := range owners {
				for _, id := range ids {
					want := each[0].Selection.Allows(owner, id) && each[1].Selection.Allows(owner, id)
					if got := required.Allows(owner, id); got != want {
						t.Fatalf("%+v: Required reaches (%s, %q) %v, each permission says %v", grants, owner, id, got, want)
					}
					wantSelected := each[0].Selection.OwnerSelected().Allows(owner, id) && each[1].Selection.OwnerSelected().Allows(owner, id)
					if got := selected.Allows(owner, id); got != wantSelected {
						t.Fatalf("%+v: RequiredOwnerSelected reaches (%s, %q) %v, each permission's owner-selected grants say %v", grants, owner, id, got, wantSelected)
					}
					if got := required.OwnerSelected().Allows(owner, id); got != wantSelected {
						t.Fatalf("%+v: Required().OwnerSelected() reaches (%s, %q) %v, each permission's owner-selected grants say %v", grants, owner, id, got, wantSelected)
					}
					if id == "" && want {
						wantOwners = append(wantOwners, owner)
					}
					if id == "" && wantSelected {
						wantSelectedOwners = append(wantSelectedOwners, owner)
					}
				}
			}
			// With the whole kind held, no owner is listed: Whole says so.
			if !wantWhole && !slices.Equal(required.Owners(), wantOwners) {
				t.Fatalf("%+v: Required owners %v, each permission says %v", grants, required.Owners(), wantOwners)
			}
			if !slices.Equal(selected.Owners(), wantSelectedOwners) || !slices.Equal(required.OwnerSelected().Owners(), wantSelectedOwners) {
				t.Fatalf("%+v: owner-selected owners %v and %v, each permission's owner-selected grants say %v", grants, selected.Owners(), required.OwnerSelected().Owners(), wantSelectedOwners)
			}
		}
	}
}

// Apart is the hop's refusal, read by the module: over every way two required
// permissions can each be held, it is exactly the decision the hop makes on
// the scopes those grants are (policy.Method.Apart), so a verifier and the
// hop in front of it never read one call two ways. A call that is apart
// reaches nothing, owner-selected or not; a call that reaches something is
// never apart.
func TestApartIsWhatTheHopRefusesAndReachesNothing(t *testing.T) {
	const records = "records.records"
	terms := [][2]any{
		{"", []string(nil)}, {"installation-a", []string(nil)}, {"installation-b", []string(nil)},
		{"installation-a", []string{"r-1", "r-2"}}, {"installation-a", []string{"r-2"}}, {"installation-b", []string{"r-1"}}, {"", []string{"r-1", "r-3"}},
	}
	var choices [][]int
	choices = append(choices, nil)
	for i := range terms {
		choices = append(choices, []int{i})
		for j := i + 1; j < len(terms); j++ {
			choices = append(choices, []int{i, j})
		}
	}
	apart, together := 0, 0
	for _, reads := range choices {
		for _, writes := range choices {
			var grants []hop.Grant
			var scopes []*basev1.WorkScopeV1
			hold := func(action string, chosen []int) {
				for _, i := range chosen {
					owner, ids := terms[i][0].(string), terms[i][1].([]string)
					grants = append(grants, holds(records, action, owner, ids...))
					scopes = append(scopes, &basev1.WorkScopeV1{ResourceKind: records, Actions: []string{action}, ResourceOwnerId: owner, ResourceIds: ids})
				}
			}
			hold("read", reads)
			hold("write", writes)
			a := hop.AdmissionOf(readsAndWrites, "/records.v1.Records/Write", grants)
			refused := readsAndWrites.Apart(scopes) != nil
			if a.Apart() != refused {
				t.Fatalf("%+v: the module reads apart=%v and the hop decides %v", grants, a.Apart(), refused)
			}
			if a.Apart() {
				apart++
				if !a.Required().Empty() || !a.RequiredOwnerSelected().Empty() {
					t.Fatalf("%+v: apart, and Required reaches %s", grants, reach(a.Required()))
				}
			}
			if !a.Required().Empty() {
				together++
			}
		}
	}
	if apart == 0 || together == 0 {
		t.Fatalf("%d apart, %d held together: the comparison proved nothing", apart, together)
	}

	for name, c := range map[string]struct {
		declared policy.Method
		grants   []hop.Grant
		apart    bool
	}{
		"a read on one owner and a write on another":             {readsAndWrites, []hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "installation-b")}, true},
		"two kinds held on different owners":                     {recordAndType, []hop.Grant{holds(records, "read", "installation-a"), holds("records.types", "read", "installation-b")}, true},
		"resources named on different owners":                    {readsAndWrites, []hop.Grant{holds(records, "read", "installation-a", "r-1"), holds(records, "write", "installation-b", "r-1")}, true},
		"one owner, resources named apart, is the module's":      {readsAndWrites, []hop.Grant{holds(records, "read", "installation-a", "r-1"), holds(records, "write", "installation-a", "r-2")}, false},
		"the whole kind is held together with anything":          {readsAndWrites, []hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "")}, false},
		"resources named with no owner are held on any owner":    {readsAndWrites, []hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "", "r-1")}, false},
		"one required permission held nowhere is unmet":          {readsAndWrites, []hop.Grant{holds(records, "read", "installation-a")}, false},
		"what is carried on another owner is not required there": {carriesContent, []hop.Grant{holds(records, "read", "installation-a"), holds(records, "write_content", "installation-b")}, false},
		"one permission required":                                {policy.Method{Requires: readsAndWrites.Requires[:1]}, []hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "installation-b")}, false},
		"a method that requires nothing":                         {policy.Method{AnyCheckedCaller: true}, []hop.Grant{holds(records, "read", "installation-a")}, false},
		"a declaration that says two things":                     {policy.Method{AnyCheckedCaller: true, Requires: readsAndWrites.Requires}, []hop.Grant{holds(records, "read", "installation-a"), holds(records, "write", "installation-b")}, false},
	} {
		if got := hop.AdmissionOf(c.declared, "/records.v1.Records/Write", c.grants).Apart(); got != c.apart {
			t.Errorf("%s: apart reads %v, want %v", name, got, c.apart)
		}
	}
	var none *hop.Admission
	if none.Apart() {
		t.Error("no admission reads as apart")
	}
}
