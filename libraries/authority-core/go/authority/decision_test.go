package authority_test

import (
	"context"
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

// decisions is a harness whose host is told every decision.
type decisions struct {
	*harness
	svc  *authority.Service
	seen []authority.Decision
	fail error
}

func newDecisions(t *testing.T) *decisions {
	t.Helper()
	d := &decisions{harness: newHarness(t)}
	cfg := d.cfg
	cfg.Advisory = true // this host serves advice, so an advisory decision is told as one
	cfg.Decisions = func(_ context.Context, got authority.Decision) error {
		d.seen = append(d.seen, got)
		return d.fail
	}
	var err error
	if d.svc, err = authority.New(d.store, cfg); err != nil {
		t.Fatal(err)
	}
	d.grant("a", "user", "maya")
	return d
}

// one is the single decision do was told of, and do's error.
func (d *decisions) one(t *testing.T, do func() error) (authority.Decision, error) {
	t.Helper()
	before := len(d.seen)
	err := do()
	if got := len(d.seen) - before; got != 1 {
		t.Fatalf("the host was told %d decisions %+v, want exactly one (the call answered %v)", got, d.seen[before:], err)
	}
	return d.seen[len(d.seen)-1], err
}

// told requires do to be admitted (refusal "") or refused naming refusal,
// and the one decision the host was told to be want, with the refusal's own
// reason and a task exactly when a capability was issued or checked.
func (d *decisions) told(t *testing.T, name string, do func() error, want authority.Decision, refusal string, task bool) authority.Decision {
	t.Helper()
	got, err := d.one(t, do)
	if refusal == "" {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want.Outcome = authority.Admitted
	} else {
		if !want.Advisory {
			refused(t, err, refusal)
			if got.Reason != err.Error() {
				t.Fatalf("%s: the decision's reason is %q, and the caller was refused %q", name, got.Reason, err)
			}
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		refused(t, errors.New(got.Reason), refusal)
		want.Outcome = authority.Refused
	}
	if (got.Task != "") != task {
		t.Fatalf("%s: task %q, want one: %t", name, got.Task, task)
	}
	seen := got
	seen.Reason, seen.Task = "", ""
	if seen != want {
		t.Fatalf("%s:\n got %+v\nwant %+v", name, seen, want)
	}
	return got
}

// Owner decision 11: the authority's decisions and refusals become rows of
// the host's journal. The host is told each one, once, admitted or refused,
// with where, who, what was asked and why it was refused: a refused ask still
// names its organisation and its asker, which the error alone does not.
func TestTheHostIsToldEveryDecision(t *testing.T) {
	d := newDecisions(t)
	maya, remi := d.person("maya"), d.person("remi")
	instA := d.inst(acme, "a")
	read := []*basev0.WorkScopeV1{owned(kind, instA.PrincipalID, []string{"read"})}

	var root, child authority.Issued
	t.Run("a person's issue", func(t *testing.T) {
		d.told(t, "admitted", func() (err error) {
			root, err = d.svc.IssueForPerson(d.ctx, maya, authority.IssueRequest{Audience: "a"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssuePerson, Organization: acme, Owner: "maya", Actor: "maya", Audience: "a", Installation: instA.ID}, "", true)
		d.told(t, "refused", func() error {
			_, err := d.svc.IssueForPerson(d.ctx, remi, authority.IssueRequest{Audience: "a"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssuePerson, Code: authority.CodeDenied, Organization: acme, Owner: "remi", Actor: "remi", Audience: "a"}, "remi holds no role on a", false)
		d.told(t, "an audience nobody composed", func() error {
			_, err := d.svc.IssueForPerson(d.ctx, maya, authority.IssueRequest{Audience: "nowhere"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssuePerson, Code: authority.CodeNotFound, Organization: acme, Owner: "maya", Actor: "maya", Audience: "nowhere"}, "nowhere", false)
	})
	t.Run("a module's hop", func(t *testing.T) {
		hop := authority.Decision{Kind: authority.DecisionIssueChild, Organization: acme, Owner: "maya", Actor: "a", Audience: "store", Binding: "store"}
		admitted := hop
		admitted.Installation = instA.ID
		got := d.told(t, "admitted", func() (err error) {
			child, err = d.svc.IssueChild(d.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			return err
		}, admitted, "", true)
		if got.Task != root.Context.GetTaskId() {
			t.Fatalf("the hop's task is %q, and its parent's is %q", got.Task, root.Context.GetTaskId())
		}
		// Refused after the parent verified: the row is the owner's, proven.
		widened := hop
		widened.Code = authority.CodeDenied
		d.told(t, "refused", func() error {
			_, err := d.svc.IssueChild(d.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store", Scopes: []*basev0.WorkScopeV1{sc(kind, "admin")}})
			return err
		}, widened, "a child widens what its owner holds", true)
		// A parent that is no capability names nobody: the asker alone.
		d.told(t, "no capability", func() error {
			_, err := d.svc.IssueChild(d.ctx, "not-a-capability", authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssueChild, Code: authority.CodeUnauthenticated, Actor: "a", Audience: "store", Binding: "store"}, "work context", false)
	})
	t.Run("a page's call is one decision", func(t *testing.T) {
		d.told(t, "admitted", func() error {
			_, err := d.svc.IssueForPage(d.ctx, maya, "a", authority.IssueRequest{Audience: "store"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssuePage, Organization: acme, Owner: "maya", Actor: "a", Audience: "store", Binding: "store", Installation: instA.ID}, "", true)
		d.told(t, "its own module", func() error {
			_, err := d.svc.IssueForPage(d.ctx, maya, "a", authority.IssueRequest{Audience: "a"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssuePage, Organization: acme, Owner: "maya", Actor: "maya", Audience: "a", Installation: instA.ID}, "", true)
		d.told(t, "refused", func() error {
			_, err := d.svc.IssueForPage(d.ctx, remi, "a", authority.IssueRequest{Audience: "store"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssuePage, Code: authority.CodeDenied, Organization: acme, Owner: "remi", Actor: "remi", Audience: "store", Binding: "store"}, "remi holds no role on a", false)
	})
	t.Run("a workload's issue", func(t *testing.T) {
		d.told(t, "admitted", func() error {
			_, err := d.svc.IssueForWorkload(d.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "self", Organization: acme})
			return err
		}, authority.Decision{Kind: authority.DecisionIssueWorkload, Organization: acme, Owner: "store", Actor: "store", Audience: "store", Binding: "self", Installation: d.inst(acme, "store").ID}, "", true)
		d.told(t, "refused", func() error {
			_, err := d.svc.IssueForWorkload(d.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "undeclared", Audience: "store", Organization: acme})
			return err
		}, authority.Decision{Kind: authority.DecisionIssueWorkload, Code: authority.CodeNotFound, Organization: acme, Owner: "store", Actor: "store", Audience: "store", Binding: "undeclared"}, "undeclared", false)
	})
	t.Run("an installation's issue", func(t *testing.T) {
		d.told(t, "admitted", func() error {
			_, err := d.svc.IssueForInstallation(d.ctx, authority.Workload{Module: "a"}, instA.ID, authority.IssueRequest{Audience: "a"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssueInstallation, Organization: acme, Owner: instA.PrincipalID, Actor: instA.PrincipalID, Audience: "a", Installation: instA.ID}, "", true)
		// Refused: the asker is the workload, the owner what it asked to act as.
		d.told(t, "another solution's workload", func() error {
			_, err := d.svc.IssueForInstallation(d.ctx, authority.Workload{Module: "b"}, instA.ID, authority.IssueRequest{Audience: "a"})
			return err
		}, authority.Decision{Kind: authority.DecisionIssueInstallation, Code: authority.CodeDenied, Organization: acme, Owner: instA.PrincipalID, Actor: "b", Audience: "a", Installation: instA.ID}, "installed solution's workload", false)
	})
	t.Run("an issue from a delegation", func(t *testing.T) {
		granted, err := d.svc.Delegate(d.ctx, maya, "a", read, "a run", 3600)
		if err != nil {
			t.Fatal(err)
		}
		d.seen = nil // Delegate is a change of authority, journaled, and no decision here
		from := authority.Decision{Kind: authority.DecisionIssueDelegation, Organization: acme, Owner: "maya", Actor: "a", Audience: "store", Binding: "store", Delegation: granted.ID}
		admitted := from
		admitted.Installation = instA.ID
		d.told(t, "admitted", func() error {
			_, err := d.svc.IssueForDelegation(d.ctx, granted.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			return err
		}, admitted, "", true)
		// Refused before the binding's audience was read: the ask named none.
		other := from
		other.Code, other.Actor, other.Audience = authority.CodeDenied, "b", ""
		d.told(t, "refused", func() error {
			_, err := d.svc.IssueForDelegation(d.ctx, granted.ID, authority.Workload{Module: "b"}, authority.IssueRequest{Binding: "store"})
			return err
		}, other, "is granted to a, not b", false)
	})
	t.Run("a check", func(t *testing.T) {
		checked := authority.Decision{Kind: authority.DecisionCheck, Organization: acme, Owner: "maya", Actor: "maya", Audience: "a", Installation: instA.ID}
		got := d.told(t, "admitted", func() error {
			_, _, _, err := d.svc.CheckMethod(d.ctx, root.Token, "a", "", false)
			return err
		}, checked, "", true)
		if !got.AdmittedCheck() {
			t.Fatal("an admitted check does not say it is one")
		}
		// A capability presented where it is not addressed does not verify:
		// what it names is what it claims.
		elsewhere := checked
		elsewhere.Audience, elsewhere.Code, elsewhere.Claimed = "store", authority.CodeUnauthenticated, true
		d.told(t, "at another audience", func() error {
			_, _, _, err := d.svc.CheckMethod(d.ctx, root.Token, "store", "", false)
			return err
		}, elsewhere, "audience", true)
		d.told(t, "no capability", func() error {
			_, _, _, err := d.svc.CheckMethod(d.ctx, "not-a-capability", "a", "/a.Service/Read", false)
			return err
		}, authority.Decision{Kind: authority.DecisionCheck, Code: authority.CodeUnauthenticated, Audience: "a", Method: "/a.Service/Read"}, "work context", false)

		const method = "/tools.v1.Tools/List"
		tools := domain.Module{Name: "tools", Principal: "tools", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
			ResourceKinds: []*basev0.WorkScopeV1{sc("tools.item", "read")},
			Methods:       map[string]domain.MethodPolicy{method: {Requires: []*basev0.WorkScopeV1{sc("tools.item", "read")}}},
			Bindings:      map[string]domain.Binding{"a": {ID: "a", Audience: "a", InvokeScopes: []*basev0.WorkScopeV1{sc("a.note", "read", "write")}}}}
		if _, err := d.svc.ApplyModule(d.ctx, tools); err != nil {
			t.Fatal(err)
		}
		at, err := d.svc.IssueForPerson(d.ctx, maya, authority.IssueRequest{Audience: "tools", Binding: "a"})
		if err != nil {
			t.Fatal(err)
		}
		d.seen = nil
		method1 := authority.Decision{Kind: authority.DecisionCheck, Code: authority.CodeDenied, Organization: acme, Owner: "maya", Actor: "maya", Audience: "tools", Method: method, Installation: d.inst(acme, "tools").ID}
		d.told(t, "a method the capability does not cover", func() error {
			_, _, _, err := d.svc.CheckMethod(d.ctx, at.Token, "tools", method, false)
			return err
		}, method1, "requires", true)
		advised := method1
		advised.Advisory = true
		d.told(t, "the same, advisory", func() error {
			verified, _, refusal, err := d.svc.CheckMethod(d.ctx, at.Token, "tools", method, true)
			if err == nil && (verified == nil || refusal == nil) {
				t.Fatal("an advisory check lost the capability or the refusal")
			}
			return err
		}, advised, "requires", true)
	})
	t.Run("a resource question", func(t *testing.T) {
		listed := authority.Decision{Kind: authority.DecisionListResources, Organization: acme, Owner: "maya", Actor: "a", Audience: "store", Binding: child.Context.GetOperationBinding().GetBindingId(), Installation: instA.ID}
		got := d.told(t, "admitted", func() error {
			_, err := d.svc.ListResources(d.ctx, child.Token, "store", kind, "read")
			return err
		}, listed, "", true)
		if !got.AdmittedCheck() || got.Binding == "" {
			t.Fatalf("an admitted resource question: %+v", got)
		}
		listed.Code = authority.CodeDenied
		d.told(t, "refused", func() error {
			_, err := d.svc.ListResources(d.ctx, child.Token, "store", kind, "admin")
			return err
		}, listed, "holds no", true)
	})
}

// A host that cannot record a decision fails the operation: no capability is
// handed out and no check is answered on a decision nobody recorded. A
// refusal stays the refusal it was.
func TestADecisionTheHostCannotRecordFailsTheOperation(t *testing.T) {
	d := newDecisions(t)
	maya := d.person("maya")
	root := d.must(d.svc.IssueForPerson(d.ctx, maya, authority.IssueRequest{Audience: "a"}))
	unavailable := errors.New("the journal is unavailable")
	d.fail = unavailable

	if got, err := d.svc.IssueForPerson(d.ctx, maya, authority.IssueRequest{Audience: "a"}); !errors.Is(err, unavailable) || got.Token != "" || got.Context != nil {
		t.Fatalf("an issue the host could not record answered %v with a capability: %t", err, got.Token != "")
	}
	if verified, _, _, err := d.svc.CheckMethod(d.ctx, root.Token, "a", "", false); !errors.Is(err, unavailable) || verified != nil {
		t.Fatalf("a check the host could not record answered %v, verified: %t", err, verified != nil)
	}
	if grants, err := d.svc.IssueChild(d.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"}); !errors.Is(err, unavailable) || grants.Token != "" {
		t.Fatalf("a hop the host could not record answered %v", err)
	}
	_, err := d.svc.IssueForPerson(d.ctx, d.person("remi"), authority.IssueRequest{Audience: "a"})
	refused(t, err, "remi holds no role on a")
	code(t, err, domain.Denied)
	if !errors.Is(err, unavailable) {
		t.Fatalf("a refusal the host could not record does not say so: %v", err)
	}
	_, _, _, err = d.svc.CheckMethod(d.ctx, "not-a-capability", "a", "", false)
	if !errors.Is(err, workcontext.ErrInvalid) && !errors.Is(err, workcontext.ErrNotACoreToken) || !errors.Is(err, unavailable) {
		t.Fatalf("a refused check the host could not record: %v", err)
	}
}

// With no hook the authority tells nobody and answers as it always did: the
// rest of this package's tests run that way. A host that keeps refusals and
// issuances skips an admitted check on one comparison.
func TestAHostSkipsAdmittedChecksOnOneComparison(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "user", "maya")
	var kept []authority.Decision
	cfg := h.cfg
	cfg.Decisions = func(_ context.Context, d authority.Decision) error {
		if d.AdmittedCheck() {
			return nil
		}
		kept = append(kept, d)
		return nil
	}
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	root := h.must(svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "a"}))
	for range 3 {
		if _, _, _, err := svc.CheckMethod(h.ctx, root.Token, "a", "", false); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := svc.CheckMethod(h.ctx, root.Token, "store", "", false); err == nil {
		t.Fatal("a capability was admitted where it is not addressed")
	}
	if len(kept) != 2 || kept[0].Kind != authority.DecisionIssuePerson || kept[1].Kind != authority.DecisionCheck || kept[1].Outcome != authority.Refused {
		t.Fatalf("kept %+v, want the issue and the refused check", kept)
	}
}

// A client's issue from a person's delegation is told as the grantor's work,
// the client its actor; refused, it still names whose delegation was asked.
func TestAClientsIssueFromADelegationIsToldAsItsGrantors(t *testing.T) {
	h, c, granted := clientGrant(t)
	var seen []authority.Decision
	cfg := h.cfg
	cfg.Decisions = func(_ context.Context, d authority.Decision) error {
		seen = append(seen, d)
		return nil
	}
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IssueForClientDelegation(h.ctx, granted.ID, c.ID, granted.Resource, authority.IssueRequest{}); err != nil {
		t.Fatal(err)
	}
	_, err = svc.IssueForClientDelegation(h.ctx, granted.ID, "another-client", granted.Resource, authority.IssueRequest{})
	refused(t, err, "belongs to another client")
	if len(seen) != 2 {
		t.Fatalf("the host was told %+v, want the two decisions", seen)
	}
	want := authority.Decision{Kind: authority.DecisionIssueClientDelegation, Outcome: authority.Admitted, Organization: acme, Owner: "maya", Actor: c.ID,
		Audience: "a", Installation: h.inst(acme, "a").ID, Delegation: granted.ID, Task: seen[0].Task}
	if seen[0] != want || want.Task == "" {
		t.Fatalf("admitted:\n got %+v\nwant %+v", seen[0], want)
	}
	want = authority.Decision{Kind: authority.DecisionIssueClientDelegation, Outcome: authority.Refused, Code: authority.CodeDenied, Reason: err.Error(),
		Organization: acme, Owner: "maya", Actor: "another-client", Audience: "a", Delegation: granted.ID}
	if seen[1] != want {
		t.Fatalf("refused:\n got %+v\nwant %+v", seen[1], want)
	}
}
