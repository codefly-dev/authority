package decide_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

const getType = "/store.v1.Store/GetType"

// shelf is an owner-aware module serving store.types; catalog is a module page
// reaching it for a person through "rows" and alone through "types".
func traced(policy domain.MethodPolicy) decide.Call {
	types := func(actions ...string) decide.Scopes { return decide.Scopes{ws("store.types", nil, actions...)} }
	shelf := domain.Module{Name: "shelf", Principal: "shelf", Generation: 1, OwnerAware: true,
		ResourceKinds: types("define", "read"), Methods: map[string]domain.MethodPolicy{getType: policy}}
	catalog := domain.Module{Name: "catalog", Principal: "catalog", Generation: 1, Page: true,
		Bindings: map[string]domain.Binding{
			"rows":  {ID: "rows", Audience: "shelf", InvokeScopes: types("define", "read")},
			"types": {ID: "types", Audience: "shelf", HeadlessScopes: types("define", "read")},
		},
		Roles: map[string]decide.Scopes{"installer": types("read"), "steward": types("define"), "reader": types("read")}}
	return decide.Call{Caller: catalog, Audience: shelf, Method: getType, Installation: domain.Installation{ID: "i", PrincipalID: "p-1"}}
}

func verdicts(links []decide.Link) string {
	var out []string
	for _, l := range links {
		out = append(out, l.Name+"="+l.Verdict)
	}
	return strings.Join(out, " ")
}

func TestTraceNamesTheFirstRefusingLinkAndKeepsWalking(t *testing.T) {
	reads := domain.MethodPolicy{Requires: decide.Scopes{ws("store.types", nil, "read")}}
	open := domain.MethodPolicy{AnyCheckedCaller: true}
	allows := func(operation string, actions ...string) *domain.Binding {
		b := &domain.Binding{Audience: "shelf"}
		if operation == "headless" {
			b.HeadlessScopes = decide.Scopes{ws("store.types", nil, actions...)}
		} else {
			b.InvokeScopes = decide.Scopes{ws("store.types", nil, actions...)}
		}
		return b
	}
	for _, tc := range []struct {
		name          string
		call          func() decide.Call
		want          string
		first, reason string
	}{
		{"every link holds", func() decide.Call {
			c := traced(reads)
			c.Role, c.Binding, c.Envelope = "reader", "rows", allows("invoke", "define", "read")
			return c
		}, "role=admitted ceiling=admitted envelope=admitted policy=admitted owner=admitted", "", ""},
		{"the role names less than the method requires", func() decide.Call {
			c := traced(reads)
			c.Role, c.Binding, c.Envelope = "steward", "rows", allows("invoke", "define", "read")
			return c
		}, "role=refused ceiling=refused envelope=refused policy=refused owner=unproven", "role", "requires store.types:read"},
		{"the envelope grants define and no read, alone", func() decide.Call {
			c := traced(reads)
			c.Binding, c.Envelope = "types", allows("headless", "define")
			c.Statements = []decide.Statement{{Where: "permissions_gen.go", Declared: true, Policy: open}}
			return c
		}, "role=admitted ceiling=admitted envelope=refused policy=refused policy copy=refused owner=unproven", "envelope", "headless store.types:read"},
		{"an envelope withholding what this method does not need refuses nothing", func() decide.Call {
			c := traced(reads)
			c.Role, c.Binding, c.Envelope = "reader", "rows", allows("invoke", "read")
			return c
		}, "role=admitted ceiling=admitted envelope=admitted policy=admitted owner=admitted", "", ""},
		{"an envelope naming no such binding", func() decide.Call {
			c := traced(reads)
			c.Role, c.Binding = "reader", "rows"
			return c
		}, "role=admitted ceiling=admitted envelope=refused policy=refused owner=unproven", "envelope", "no operation binding"},
		{"an envelope that could not be read is never a pass", func() decide.Call {
			c := traced(reads)
			c.Role, c.Binding, c.EnvelopeUnread = "reader", "rows", "open module-envelope.yaml: no such file"
			return c
		}, "role=admitted ceiling=admitted envelope=unread policy=admitted owner=admitted", "envelope", "no such file"},
		{"declared open where owners are checked proves nothing", func() decide.Call {
			c := traced(open)
			c.Binding, c.Envelope = "types", allows("headless", "define")
			return c
		}, "role=admitted ceiling=admitted envelope=admitted policy=admitted owner=unproven", "owner", "no declaration states what it asks"},
		{"a read that arrives selected to no owner is not proven", func() decide.Call {
			c := traced(reads)
			c.Binding, c.Envelope = "types", allows("headless", "define", "read")
			return c
		}, "role=admitted ceiling=admitted envelope=admitted policy=admitted owner=unproven", "owner", "selected to no installation's owner"},
		{"a role beyond its ceiling is refused whole", func() decide.Call {
			c := traced(reads)
			c.Caller.Roles["reader"] = decide.Scopes{ws("store.types", nil, "read"), ws("store.rows", nil, "read")}
			c.Role, c.Binding, c.Envelope = "reader", "rows", allows("invoke", "define", "read")
			return c
		}, "role=admitted ceiling=refused envelope=admitted policy=admitted owner=admitted", "ceiling", "grants beyond what catalog serves"},
		{"a method the audience does not declare", func() decide.Call {
			c := traced(reads)
			c.Role, c.Binding, c.Method, c.Envelope = "reader", "rows", "/store.v1.Store/Other", allows("invoke", "read")
			return c
		}, "role=unproven ceiling=unproven envelope=refused policy=refused owner=unproven", "role", "declares no usable policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			links := decide.Trace(tc.call())
			if got := verdicts(links); got != tc.want {
				t.Fatalf("verdicts:\n got %s\nwant %s\n%+v", got, tc.want, links)
			}
			first, refused := decide.First(links)
			if first.Name != tc.first || refused != (tc.first != "") || !strings.Contains(first.Reason, tc.reason) {
				t.Fatalf("first refusing link = %q (%s), want %q naming %q", first.Name, first.Reason, tc.first, tc.reason)
			}
		})
	}
}

// A copy of the policy that disagrees with the delivered one is refused by
// name, and one that could not be read is unread: neither reads as agreement.
func TestTraceHoldsEveryCopyOfThePolicyToTheDeliveredOne(t *testing.T) {
	c := traced(domain.MethodPolicy{Requires: decide.Scopes{ws("store.types", nil, "read")}})
	c.Role, c.Binding = "reader", "rows"
	c.Envelope = &domain.Binding{Audience: "shelf", InvokeScopes: decide.Scopes{ws("store.types", nil, "read")}}
	c.Statements = []decide.Statement{
		{Where: "same", Declared: true, Policy: domain.MethodPolicy{Requires: decide.Scopes{ws("store.types", nil, "read")}}},
		{Where: "stale", Declared: true, Policy: domain.MethodPolicy{AnyCheckedCaller: true}},
		{Where: "absent"},
		{Where: "lost", Unread: "parse error"},
	}
	got := map[string]decide.Link{}
	for _, l := range decide.Trace(c) {
		got[l.Field] = l
	}
	for where, want := range map[string]string{"same": decide.Admitted, "stale": decide.Refused, "absent": decide.Refused, "lost": decide.Unread} {
		if got[where].Verdict != want {
			t.Errorf("copy %q: %s, want %s (%s)", where, got[where].Verdict, want, got[where].Reason)
		}
	}
	if r := got["stale"].Reason; !strings.Contains(r, "any checked caller") || !strings.Contains(r, "requires store.types:read") {
		t.Errorf("a disagreeing copy names both values, got %q", r)
	}
}

func TestGrantedIsWhatBothTheBindingAndTheEnvelopeName(t *testing.T) {
	asked := domain.Binding{ID: "b", Audience: "shelf",
		InvokeScopes:   decide.Scopes{ws("store.types", nil, "define", "read")},
		HeadlessScopes: decide.Scopes{ws("store.types", nil, "define")},
		LookupScopes:   decide.Scopes{ws("store.types", nil, "read")}}
	narrowed := domain.Binding{Audience: "shelf", InvokeScopes: decide.Scopes{ws("store.types", []string{"t1"}, "read")}, LookupScopes: asked.LookupScopes}
	granted, err := decide.Granted(asked, narrowed)
	if err != nil || len(granted.InvokeScopes) != 1 || granted.InvokeScopes[0].GetResourceIds()[0] != "t1" || len(granted.LookupScopes) != 1 {
		t.Fatalf("granted = %+v, %v", granted, err)
	}
	// Naming resources narrows and withholds no action; a dropped action is named.
	if got := strings.Join(decide.Withheld(asked, granted), "; "); got != "invoke store.types:define; headless store.types:define" {
		t.Fatalf("withheld = %q", got)
	}
	headlessOnly, err := decide.Granted(asked, domain.Binding{Audience: "shelf", HeadlessScopes: asked.HeadlessScopes, LookupScopes: asked.LookupScopes})
	if err != nil || len(headlessOnly.LookupScopes) != 0 {
		t.Fatalf("a lookup stands only beside an invoke: %+v, %v", headlessOnly, err)
	}
	for name, allowed := range map[string]domain.Binding{
		"another audience":  {Audience: "elsewhere", InvokeScopes: asked.InvokeScopes},
		"nothing in common": {Audience: "shelf", InvokeScopes: decide.Scopes{ws("store.rows", nil, "read")}},
	} {
		_, err := decide.Granted(asked, allowed)
		if code, refused := domain.CodeOf(err); !refused || code != domain.Denied {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
}
