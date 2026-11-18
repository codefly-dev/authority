package decide_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func ws(kind string, ids []string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceIds: ids}
}

func reads(kind string) domain.MethodPolicy {
	return domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{ws(kind, nil, "read")}}
}

// Every rule of method admission, allowed and refused, with the refusal's
// code: a method not declared is NotFound, every other refusal Denied.
func TestMethodAdmission(t *testing.T) {
	gauge := domain.Module{Name: "gauge", Principal: "gauge", Methods: map[string]domain.MethodPolicy{
		"/gauge.Service/List":                      reads("gauge.items"),
		"/gauge.Service/Edit":                      {Requires: []*basev0.WorkScopeV1{ws("gauge.items", nil, "read", "write")}},
		"/gauge.Service/Ping":                      {AnyCheckedCaller: true},
		"/gauge.Service/Both":                      {AnyCheckedCaller: true, Requires: []*basev0.WorkScopeV1{ws("gauge.items", nil, "read")}},
		"/gauge.Service/Empty":                     {},
		"GET /v1/gauge/profiles":                   reads("gauge.profiles"),
		"GET /v1/gauge/profiles/{ref}":             reads("gauge.profiles"),
		"POST /v1/gauge/matches/{match_id}:settle": {Requires: []*basev0.WorkScopeV1{ws("gauge.profiles", nil, "write")}},
		"GET /v1/gauge/{a}/x":                      {AnyCheckedCaller: true},
		"GET /v1/gauge/{b}/x":                      {AnyCheckedCaller: true},
		"GET /v1/gauge/sources/{repo=**}":          reads("gauge.profiles"),
		"POST /v1/gauge/sources/{repo=**}:settle":  reads("gauge.profiles"),
		"/gauge.v1.GaugeService/ListProfiles":      reads("gauge.profiles"),
	}}
	read := []*basev0.WorkScopeV1{ws("gauge.profiles", nil, "read")}
	type want int
	const (
		allow want = iota
		denied
		missing
	)
	for _, tc := range []struct {
		name, method string
		held         []*basev0.WorkScopeV1
		want         want
		reason       string
	}{
		{"one resource", "/gauge.Service/List", []*basev0.WorkScopeV1{ws("gauge.items", []string{"one"}, "read")}, allow, ""},
		{"several resource scopes", "/gauge.Service/List", []*basev0.WorkScopeV1{ws("gauge.items", []string{"one"}, "read"), ws("gauge.items", []string{"two"}, "read")}, allow, ""},
		{"restricted wildcard", "/gauge.Service/List", []*basev0.WorkScopeV1{ws("gauge.items", []string{"one"}, scope.AnyAction)}, allow, ""},
		{"whole kind", "/gauge.Service/List", []*basev0.WorkScopeV1{ws("gauge.items", nil, "read")}, allow, ""},
		{"whole wildcard", "/gauge.Service/Edit", []*basev0.WorkScopeV1{ws("gauge.items", nil, scope.AnyAction)}, allow, ""},
		{"whole read restricted write", "/gauge.Service/Edit", []*basev0.WorkScopeV1{ws("gauge.items", nil, "read"), ws("gauge.items", []string{"one"}, "write")}, allow, ""},
		{"checked caller", "/gauge.Service/Ping", nil, allow, ""},
		{"missing write names the restriction", "/gauge.Service/Edit", []*basev0.WorkScopeV1{ws("gauge.items", []string{"one"}, "read")}, denied, "resource-limited"},
		{"nothing held", "/gauge.Service/List", nil, denied, "it holds nothing"},
		{"owner-selected is named", "/gauge.Service/Edit", []*basev0.WorkScopeV1{{ResourceKind: "gauge.items", Actions: []string{"read"}, ResourceOwnerId: "p"}}, denied, "owner-selected"},
		{"both requires and any caller", "/gauge.Service/Both", read, denied, "both that it requires"},
		{"a policy declaring nothing", "/gauge.Service/Empty", read, denied, "declares no policy"},
		{"an undeclared method", "/gauge.Service/Gone", read, missing, "serves no method"},
		{"route", "GET /v1/gauge/profiles", read, allow, ""},
		{"route template", "GET /v1/gauge/profiles/pro-1", read, allow, ""},
		{"route matched, write not held", "POST /v1/gauge/matches/m-1:settle", read, denied, "gauge.profiles:write"},
		{"extra segment", "GET /v1/gauge/profiles/pro-1/extra", read, missing, ""},
		{"other verb", "DELETE /v1/gauge/profiles/pro-1", read, missing, ""},
		{"an empty segment", "POST /v1/gauge/matches/:settle", read, missing, ""},
		{"two templates match", "GET /v1/gauge/ambiguous/x", read, denied, "more than one declared route"},
		{"rest of path", "GET /v1/gauge/sources/github.com/acme/repo", read, allow, ""},
		{"empty rest of path", "GET /v1/gauge/sources/", read, missing, ""},
		{"verb after the rest", "POST /v1/gauge/sources/github.com/acme/repo:settle", read, allow, ""},
		{"HTTP never borrows a protobuf policy", "POST /gauge.v1.GaugeService/ListProfiles", read, missing, ""},
		{"a procedure", "/gauge.v1.GaugeService/ListProfiles", read, allow, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := decide.AdmitMethod(gauge, tc.method, tc.held)
			switch tc.want {
			case allow:
				if err != nil {
					t.Fatal(err)
				}
				return
			case denied:
				wantCode(t, err, domain.Denied)
			case missing:
				wantCode(t, err, domain.NotFound)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("refusal %q does not name %q", err, tc.reason)
			}
		})
	}
	t.Run("a module declaring no method policy admits nothing", func(t *testing.T) {
		err := decide.AdmitMethod(domain.Module{Principal: "oracle"}, "/oracle/Read", read)
		wantCode(t, err, domain.Denied)
		if !strings.Contains(err.Error(), "no method policy") {
			t.Fatal(err)
		}
	})
}

func wantCode(t *testing.T, err error, want domain.Code) {
	t.Helper()
	if got, ok := domain.CodeOf(err); !ok || got != want {
		t.Fatalf("want code %v, got %v (%v)", want, got, err)
	}
}

// A delivery never selects an owner: anywhere one appears is refused by name,
// and what a module serves includes every kind its methods require.
func TestADeliveryNamesNoOwnerAndServesWhatItsMethodsRequire(t *testing.T) {
	owner := &basev0.WorkScopeV1{ResourceKind: "k", Actions: []string{"read"}, ResourceOwnerId: "u"}
	base := func() domain.Module {
		return domain.Module{Name: "m", Principal: "m", Kind: domain.KindModule, Generation: 1, Bindings: map[string]domain.Binding{}}
	}
	for name, mutate := range map[string]func(*domain.Module){
		"serves": func(m *domain.Module) { m.ResourceKinds = []*basev0.WorkScopeV1{owner} },
		"invoke": func(m *domain.Module) {
			m.Bindings["b"] = domain.Binding{ID: "b", Audience: "x", InvokeScopes: []*basev0.WorkScopeV1{owner}}
		},
		"lookup": func(m *domain.Module) {
			m.Bindings["b"] = domain.Binding{ID: "b", Audience: "x", InvokeScopes: []*basev0.WorkScopeV1{ws("k", nil, "read")}, LookupScopes: []*basev0.WorkScopeV1{owner}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(&m)
			err := decide.ValidateModule(m)
			wantCode(t, err, domain.Denied)
			if !strings.Contains(err.Error(), "never selects an owner") {
				t.Fatal(err)
			}
		})
	}
	m := base()
	m.ResourceKinds = []*basev0.WorkScopeV1{ws("own", nil, "read")}
	m.Methods = map[string]domain.MethodPolicy{"/m/Write": {Requires: []*basev0.WorkScopeV1{ws("other", nil, "write")}}, "/m/Read": reads("own")}
	served := decide.Served(m)
	if !scope.Same(served, scope.Normalize([]*basev0.WorkScopeV1{ws("other", nil, "write"), ws("own", nil, "read")})) {
		t.Fatalf("served %v", served)
	}
}

// A declaration that says both things is refused however its requirement is
// spelled: one naming no action still contradicts any_checked_caller, and the
// admission never relies on a delivery having validated it first (a policy
// also arrives from an approved reach and from a host's own store).
func TestAContradictoryPolicyIsRefusedEvenWithAnEmptyRequirement(t *testing.T) {
	for name, requires := range map[string][]*basev0.WorkScopeV1{
		"a requirement with an action": {{ResourceKind: "doc", Actions: []string{"read"}}},
		"a requirement with no action": {{ResourceKind: "doc"}},
	} {
		err := decide.AdmitPolicy("m", "/s.S/M", domain.MethodPolicy{AnyCheckedCaller: true, Requires: requires}, nil)
		if err == nil || !strings.Contains(err.Error(), "both that it requires scopes and that it requires none") {
			t.Errorf("%s beside any_checked_caller: %v, want it refused as contradictory", name, err)
		}
	}
	// A kind is matched as declared, never re-split at a colon.
	held := []*basev0.WorkScopeV1{{ResourceKind: "a:b", Actions: []string{"read"}}}
	if err := decide.AdmitPolicy("m", "/s.S/M", domain.MethodPolicy{Requires: held}, held); err != nil {
		t.Errorf("a kind containing a colon is not matched as declared: %v", err)
	}
}

// A method requiring two permissions is admitted where the call holds them
// together. Held on owners that share none (a read on one installation's
// resources, a write on another's), the call holds them on nothing and the
// authority refuses it, saying where each is held, so the hop that asked
// passes the refusal on instead of a call its module serves nothing of. A
// grant that selects no owner is held together with anything.
func TestAMethodRequiringTwoPermissionsIsRefusedWhereTheyShareNoOwner(t *testing.T) {
	owned := func(owner string, ids []string, actions ...string) *basev0.WorkScopeV1 {
		return &basev0.WorkScopeV1{ResourceKind: "gauge.items", Actions: actions, ResourceOwnerId: owner, ResourceIds: ids}
	}
	edit := domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{ws("gauge.items", nil, "read", "write")}}
	gauge := domain.Module{Name: "gauge", Principal: "gauge", Methods: map[string]domain.MethodPolicy{"/gauge.Service/Edit": edit, "/gauge.Service/List": reads("gauge.items")}}
	for name, held := range map[string][]*basev0.WorkScopeV1{
		"a read on one owner, a write on another": {owned("installation-a", nil, "read"), owned("installation-b", nil, "write")},
		"named resources on different owners":     {owned("installation-a", []string{"i-1"}, "read"), owned("installation-b", []string{"i-1"}, "write")},
		"two reads and a write on three owners":   {owned("installation-a", nil, "read"), owned("installation-b", nil, "write"), owned("installation-c", nil, "read")},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			err := decide.AdmitMethod(gauge, "/gauge.Service/Edit", held)
			wantCode(t, err, domain.Denied)
			for _, want := range []string{"gauge requires gauge.items:read, gauge.items:write together for /gauge.Service/Edit", "no owner in common",
				"gauge.items:read on installation-a", "gauge.items:write on installation-b"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not say %q", err, want)
				}
			}
			// One permission required: the same call lists.
			if err := decide.AdmitMethod(gauge, "/gauge.Service/List", held); err != nil {
				t.Fatalf("a method requiring the read alone is refused: %v", err)
			}
		})
	}
	for name, held := range map[string][]*basev0.WorkScopeV1{
		"both on one owner":                           {owned("installation-a", nil, "read", "write")},
		"an owner in common among several":            {owned("installation-a", nil, "read"), owned("installation-b", nil, "read", "write"), owned("installation-c", nil, "write")},
		"the write on the whole kind":                 {owned("installation-a", nil, "read"), ws("gauge.items", nil, "write")},
		"the whole kind":                              {ws("gauge.items", nil, "read", "write")},
		"every action on the read's owner":            {owned("installation-a", nil, "read"), owned("installation-a", nil, scope.AnyAction)},
		"resources named with no owner":               {owned("installation-a", nil, "read"), ws("gauge.items", []string{"i-1"}, "write")},
		"one owner, resources named apart":            {owned("installation-a", []string{"i-1"}, "read"), owned("installation-a", []string{"i-2"}, "write")},
		"a whole-kind read beside two owners' writes": {ws("gauge.items", nil, "read"), owned("installation-a", nil, "write"), owned("installation-b", nil, "write")},
	} {
		t.Run("admitted: "+name, func(t *testing.T) {
			if err := decide.AdmitMethod(gauge, "/gauge.Service/Edit", held); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("a permission held nowhere is refused as not held", func(t *testing.T) {
		err := decide.AdmitMethod(gauge, "/gauge.Service/Edit", []*basev0.WorkScopeV1{owned("installation-a", nil, "read")})
		wantCode(t, err, domain.Denied)
		if !strings.Contains(err.Error(), "which the call does not hold") || strings.Contains(err.Error(), "no owner in common") {
			t.Fatal(err)
		}
	})
}
