package hop

// What admitted a call, handed to the module so that no handler names a
// permission.
//
// The hop admits a call on its method's declaration (authority.hop.v1.policy)
// and stamps, beside who the call is for, everything the call holds with the
// selection each grant carries: the whole kind, one owner's resources, or
// named resources (AdmittedKey). The module's Verifier authenticates that
// stamp exactly as it does the identity: the value must be the one derived
// from the Work Context it authenticated, or the call is refused. It then
// reads the method's own declaration from the contract the module serves and
// hands the handler an Admission: for what the method requires, and for what
// it carries, which owners and which resources the call holds it on.
//
// A handler that must narrow a query reads Admitted(ctx).Required() (the
// owners the caller may see) or .Carried() (how far the narrower of two
// declared scopes reaches, content against metadata), and writes no kind and
// no action. Admission was decided by the hop; nothing here decides it again.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// AdmittedKey carries what the admitted call holds, each grant with its
// selection: EncodeGrants of Identity.Grants. Like every stamp key it is the
// hop's to write: a caller's is stripped, and a module refuses one that is not
// what the authenticated Work Context says.
const AdmittedKey = StampPrefix + "admitted"

// Grant is one action on one resource kind as the call holds it, with its
// selection: no Owner and no Resources is the whole kind; an Owner alone is
// every resource that owner holds; Resources are named resources, of Owner
// when it is set. An action of policy.AnyAction holds every action.
type Grant struct {
	Kind      string
	Action    string
	Owner     string
	Resources []string
}

// grantsOf is what a Work Context holds once every actor has narrowed it: the
// last actor's granted scopes, which the authority attenuated from each hop
// before it, or the owner's authority scopes when no one acts for them. It is
// the scopes workcontext.Claims answers Allows from, one grant per action,
// sorted, so the hop and the module derive the same value.
func grantsOf(wc *basev0.WorkContextV1) []Grant {
	scopes := wc.GetAuthorityScopes()
	if chain := wc.GetActorChain(); len(chain) > 0 {
		scopes = chain[len(chain)-1].GetGrantedScopes()
	}
	var out []Grant
	for _, scope := range scopes {
		ids := slices.Clone(scope.GetResourceIds())
		slices.Sort(ids)
		ids = slices.Compact(ids)
		for _, action := range scope.GetActions() {
			out = append(out, Grant{Kind: scope.GetResourceKind(), Action: action, Owner: scope.GetResourceOwnerId(), Resources: ids})
		}
	}
	return canonical(out)
}

func canonical(grants []Grant) []Grant {
	out := make([]Grant, 0, len(grants))
	for _, g := range grants {
		ids := slices.Clone(g.Resources)
		slices.Sort(ids)
		out = append(out, Grant{Kind: g.Kind, Action: g.Action, Owner: g.Owner, Resources: slices.Compact(ids)})
	}
	slices.SortFunc(out, compareGrants)
	return slices.CompactFunc(out, func(a, b Grant) bool { return compareGrants(a, b) == 0 })
}

func compareGrants(a, b Grant) int {
	for _, pair := range [][2]string{{a.Kind, b.Kind}, {a.Action, b.Action}, {a.Owner, b.Owner}} {
		if c := strings.Compare(pair[0], pair[1]); c != 0 {
			return c
		}
	}
	return slices.Compare(a.Resources, b.Resources)
}

// EncodeGrants is AdmittedKey's value: unpadded base64url of a JSON array with
// one [kind, action, owner, [resource ids]] entry per grant, sorted by kind,
// action, owner, then ids, the ids sorted and each entry once. A verifier in
// another language decodes it and compares the entries it derives from the
// Work Context it authenticated; it never trusts the value on its own.
func EncodeGrants(grants []Grant) (string, error) {
	entries := make([][]any, 0, len(grants))
	for _, g := range canonical(grants) {
		ids := g.Resources
		if ids == nil {
			ids = []string{}
		}
		entries = append(entries, []any{g.Kind, g.Action, g.Owner, ids})
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// GrantsOf decodes AdmittedKey's value. It authenticates nothing: a module
// reads Admitted, which the Verifier established.
func GrantsOf(value string) ([]Grant, error) {
	malformed := errors.New("hop: the admission stamp is malformed")
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, malformed
	}
	var entries [][]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil, malformed
	}
	out := make([]Grant, 0, len(entries))
	for _, entry := range entries {
		var g Grant
		if len(entry) != 4 || json.Unmarshal(entry[0], &g.Kind) != nil || json.Unmarshal(entry[1], &g.Action) != nil ||
			json.Unmarshal(entry[2], &g.Owner) != nil || json.Unmarshal(entry[3], &g.Resources) != nil {
			return nil, malformed
		}
		if len(g.Resources) == 0 {
			g.Resources = nil
		}
		out = append(out, g)
	}
	return out, nil
}

// Named is one term of a Selection: every resource of Owner, or the Resources
// named, of Owner when it is set. No Owner and no Resources is the whole kind.
type Named struct {
	Owner     string
	Resources []string
}

// Selection is how far a call reaches for what its method declares: the union
// of its terms. The zero Selection reaches nothing.
type Selection struct{ terms []Named }

// Empty reports that the selection reaches nothing.
func (s Selection) Empty() bool { return len(s.terms) == 0 }

// Whole reports that the call holds the declaration on the whole kind, with no
// owner selected. A module whose resources have owners decides for itself
// whether an unselected grant reaches them; OwnerSelected drops it.
func (s Selection) Whole() bool {
	return slices.ContainsFunc(s.terms, func(t Named) bool { return t.Owner == "" && len(t.Resources) == 0 })
}

// Owners are the owners whose every resource the call reaches, sorted: what a
// list narrows its query to. It is never nil, so "no owner" is never read as
// "no filter".
func (s Selection) Owners() []string {
	owners := []string{}
	for _, t := range s.terms {
		if t.Owner != "" && len(t.Resources) == 0 && !slices.Contains(owners, t.Owner) {
			owners = append(owners, t.Owner)
		}
	}
	slices.Sort(owners)
	return owners
}

// Named are the terms that name resources, for a module that honours them.
func (s Selection) Named() []Named {
	var out []Named
	for _, t := range s.terms {
		if len(t.Resources) > 0 {
			out = append(out, Named{Owner: t.Owner, Resources: slices.Clone(t.Resources)})
		}
	}
	return out
}

// OwnerSelected is the selection without the terms that name no owner: what a
// module reads when a grant that selects no owner must reach none of its
// owned resources.
func (s Selection) OwnerSelected() Selection {
	var out Selection
	for _, t := range s.terms {
		if t.Owner != "" {
			out.terms = append(out.terms, t)
		}
	}
	return out
}

// Allows reports whether the selection reaches the resource id that owner
// holds, as the module's own record names them. An empty id asks for every
// resource of that owner, which named resources never cover; a term naming an
// owner covers only that owner.
func (s Selection) Allows(owner, id string) bool {
	return slices.ContainsFunc(s.terms, func(t Named) bool {
		if t.Owner != "" && t.Owner != owner {
			return false
		}
		return len(t.Resources) == 0 || (id != "" && slices.Contains(t.Resources, id))
	})
}

// both is the selection both a and b reach.
func both(a, b Selection) Selection {
	var out Selection
	for _, x := range a.terms {
		for _, y := range b.terms {
			if x.Owner != "" && y.Owner != "" && x.Owner != y.Owner {
				continue
			}
			t := Named{Owner: x.Owner}
			if t.Owner == "" {
				t.Owner = y.Owner
			}
			switch {
			case len(x.Resources) == 0:
				t.Resources = slices.Clone(y.Resources)
			case len(y.Resources) == 0:
				t.Resources = slices.Clone(x.Resources)
			default:
				for _, id := range x.Resources {
					if slices.Contains(y.Resources, id) {
						t.Resources = append(t.Resources, id)
					}
				}
				if len(t.Resources) == 0 {
					continue
				}
			}
			if !slices.ContainsFunc(out.terms, func(have Named) bool { return have.Owner == t.Owner && slices.Equal(have.Resources, t.Resources) }) {
				out.terms = append(out.terms, t)
			}
		}
	}
	return out
}

// Held is one permission a method declares and how far the call holds it.
type Held struct {
	Permission policy.Permission
	// Carried is true for what the method carries rather than requires.
	Carried   bool
	Selection Selection
}

// Admission is what admitted one call: the method, what it declares, and how
// far the call holds each permission of that declaration.
type Admission struct {
	// Method is the procedure, or the HTTP request, the call was admitted on.
	Method string
	// Declared is false when the module's contract declares nothing for
	// Method that this verifier could read; nothing is then selected.
	Declared bool
	// AnyCheckedCaller is the method's declaration that it requires nothing:
	// the call was admitted as a checked caller, on no scope at all.
	AnyCheckedCaller bool
	held             []Held
}

// Required is how far the call holds everything the method requires: the
// owners and resources on which it holds every required permission. A method
// that requires nothing selects nothing. When a method requires permissions of
// different kinds on named resources, read Each.
func (a *Admission) Required() Selection { return a.all(false) }

// Carried is how far the call holds everything the method carries, within
// what it requires: the narrower of two declared scopes, such as content
// within metadata. Empty when the call holds only what the method requires.
func (a *Admission) Carried() Selection {
	if a == nil || !slices.ContainsFunc(a.held, func(h Held) bool { return h.Carried }) {
		return Selection{}
	}
	carried := a.all(true)
	if slices.ContainsFunc(a.held, func(h Held) bool { return !h.Carried }) {
		return both(a.all(false), carried)
	}
	return carried
}

// Each is every permission the method declares with its own selection, for
// the method that carries more than one thing. The permissions are the
// declaration's, read from the contract; a handler still writes none.
func (a *Admission) Each() []Held {
	if a == nil {
		return nil
	}
	return slices.Clone(a.held)
}

func (a *Admission) all(carried bool) Selection {
	var out Selection
	if a == nil {
		return out
	}
	first := true
	for _, h := range a.held {
		if h.Carried != carried {
			continue
		}
		if first {
			out, first = h.Selection, false
			continue
		}
		out = both(out, h.Selection)
	}
	return out
}

// AdmissionOf reads grants against one method's declaration: for each
// permission the method requires or carries, the selection of every grant
// that holds it. It is what the Verifier hands a handler; a test of a module's
// own narrowing builds one the same way.
func AdmissionOf(declared policy.Method, method string, grants []Grant) *Admission {
	a := &Admission{Method: method, Declared: declared.Declares(), AnyCheckedCaller: declared.AnyCheckedCaller}
	if declared.Validate() != nil {
		// A declaration that says two things was refused by the hop; it is
		// never read as one of them here.
		a.Declared = false
		return a
	}
	seen := map[policy.Permission]bool{}
	// What a method requires is read first: a permission it also lists as
	// carried is required.
	for n, permissions := range [][]policy.Permission{declared.Requires, declared.Carries} {
		for _, p := range permissions {
			if seen[p] {
				continue
			}
			seen[p] = true
			h := Held{Permission: p, Carried: n == 1}
			for _, g := range canonical(grants) {
				if g.Kind == p.Kind && (g.Action == p.Action || g.Action == policy.AnyAction) {
					h.Selection.terms = append(h.Selection.terms, Named{Owner: g.Owner, Resources: g.Resources})
				}
			}
			a.held = append(a.held, h)
		}
	}
	slices.SortStableFunc(a.held, func(x, y Held) int {
		if x.Carried != y.Carried {
			if y.Carried {
				return -1
			}
			return 1
		}
		return strings.Compare(x.Permission.String(), y.Permission.String())
	})
	return a
}

// Admitted is what admitted the call the module's interceptor authenticated.
// It is nil, false for a call the hop stamped no admission on (a hop older
// than this contract, or a health check); a nil Admission selects nothing.
func Admitted(ctx context.Context) (*Admission, bool) {
	id, ok := FromContext(ctx)
	if !ok || id.Admitted == nil {
		return nil, false
	}
	return id.Admitted, true
}

// Declarations hands the verifier what each method the module serves declares,
// keyed "/package.Service/Method" or, for an HTTP route, "<VERB> <template>".
// A module whose generated protobuf code is linked into its binary needs none:
// the declaration is read from the descriptors that code registers. A module
// that serves HTTP routes passes its delivered method declarations.
func Declarations(declared map[string]policy.Method) VerifierOption {
	return func(v *Verifier) { v.declared = declared }
}

// declaration is what the module declares for method: from Declarations, an
// exact entry or the one route template an HTTP request is an instance of,
// else from the contract the binary serves.
func (v *Verifier) declaration(method string) (policy.Method, bool) {
	if m, ok := v.declared[method]; ok {
		return m, true
	}
	if verb, path, ok := strings.Cut(method, " "); ok && strings.HasPrefix(path, "/") {
		var found []policy.Method
		for route, m := range v.declared {
			if want, template, ok := strings.Cut(route, " "); ok && want == verb && routing.RouteMatches(template, path) {
				found = append(found, m)
			}
		}
		// Two templates matching one request is the ambiguity the authority
		// refuses; it selects nothing here.
		if len(found) == 1 {
			return found[0], true
		}
		return policy.Method{}, false
	}
	return served(method)
}

// served reads a procedure's declaration from the descriptors registered in
// this binary, which are the contract the module publishes, compiled in.
func served(method string) (policy.Method, bool) {
	service, name, ok := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	if !ok || !strings.HasPrefix(method, "/") {
		return policy.Method{}, false
	}
	found, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return policy.Method{}, false
	}
	described, ok := found.(protoreflect.ServiceDescriptor)
	if !ok {
		return policy.Method{}, false
	}
	rpc := described.Methods().ByName(protoreflect.Name(name))
	if rpc == nil {
		return policy.Method{}, false
	}
	options, ok := rpc.Options().(*descriptorpb.MethodOptions)
	if !ok || options == nil {
		return policy.Method{}, true
	}
	declared, _ := proto.GetExtension(options, hopv1.E_Policy).(*hopv1.Policy)
	return policy.FromProto(declared), true
}

// admittedOn is what admitted the call md carries on method, or nil when the
// hop stamped none. id is the authenticated identity, which sameAsStamped has
// already held the stamp to.
func (v *Verifier) admittedOn(md metadata.MD, method string, id Identity) *Admission {
	if len(md.Get(AdmittedKey)) != 1 {
		return nil
	}
	declared, _ := v.declaration(method)
	return AdmissionOf(declared, method, id.Grants)
}
