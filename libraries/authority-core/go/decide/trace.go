package decide

import (
	"fmt"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The verdicts of one link of a traced call. Only Admitted lets the call
// through: a link that was not read, or that no declaration decides, is never
// reported as one that passed.
const (
	Admitted = "admitted" // read, and it lets the call through
	Refused  = "refused"  // read, and it refuses the call
	Unread   = "unread"   // its source could not be read, so it has no verdict
	Unproven = "unproven" // read, and no declaration states what decides it
)

// Link is one link of the chain a call travels: the Field of the declaration
// that decided it, the Value held there, and, unless it is Admitted, the
// Reason in the words of the decision that refused it.
type Link struct {
	Name, Verdict, Field, Value, Reason string
}

// Statement is one written copy of what the audience's method requires, Where
// it is written: a generated table, a published contract. Unread says why a
// copy could not be read; Declared is false for a copy that omits the method.
type Statement struct {
	Where, Unread string
	Declared      bool
	Policy        domain.MethodPolicy
}

// Call is one call to explain: a holder of Role on Caller's Installation (no
// Role is Caller acting alone, on its headless scopes) reaching Method of
// Audience through Caller's Binding. Envelope is what the host's envelope
// allows of that binding: nil is an envelope naming no such binding, unless
// EnvelopeUnread says why it could not be read. Statements are the other
// copies of Audience's policy for Method, each held to the delivered one.
type Call struct {
	Caller, Audience domain.Module
	Role, Binding    string
	Method           string
	Installation     domain.Installation
	Envelope         *domain.Binding
	EnvelopeUnread   string
	Statements       []Statement
}

// Trace walks the declared chain of one call and answers every link, in
// order: the role, the binding's ceiling, the envelope, the audience's method
// policy (and each other copy of it), and the audience's owner check. It
// stops at nothing, so a person sees everything wrong and not only the
// earliest; First names the link that refuses first.
//
// It decides nothing itself: each verdict is the answer of the decision the
// authority applies there (ValidateModule, Through, Granted, ModuleRoleAt,
// HeadlessAt, AdmitMethod). It covers one hop, from declarations alone: what
// an installation consented to, a delegation, and the handler's own check of
// each resource are not in it, and the owner link says so rather than pass.
func Trace(c Call) []Link {
	operation, acting := "invoke", fmt.Sprintf("role %q of %s", c.Role, c.Caller.Name)
	if c.Role == "" {
		operation, acting = "headless", c.Caller.Name+" acting alone"
	}
	key, served := MethodKey(c.Audience, c.Method)
	policy := c.Audience.Methods[key]
	decidable := served && (policy.AnyCheckedCaller != (len(policy.Requires) > 0))
	var links []Link
	// stage answers a link that carries scopes: refused by its own decision
	// (err), or by the audience's policy applied to what is left.
	stage := func(name, field string, carried Scopes, err error) {
		link := Link{Name: name, Verdict: Admitted, Field: field, Value: describe(carried)}
		switch {
		case err != nil:
			link.Verdict, link.Reason = Refused, err.Error()
		case !decidable:
			link.Verdict, link.Reason = Unproven, fmt.Sprintf("%s declares no usable policy for %s, so nothing says whether this is enough", c.Audience.Name, c.Method)
		default:
			if refused := AdmitPolicy(c.Audience.Principal, c.Method, policy, carried); refused != nil {
				link.Verdict, link.Reason = Refused, refused.Error()
			}
		}
		links = append(links, link)
	}

	b, declared := c.Caller.Bindings[c.Binding]
	var roleErr, ceilingErr error
	held := b.HeadlessScopes
	if c.Role == "" {
		links = append(links, Link{Name: "role", Verdict: Admitted, Field: "bindings[" + c.Binding + "].headless", Value: "no person: " + acting})
	} else {
		role, ok := c.Caller.Roles[c.Role]
		if !ok {
			roleErr = domain.Missing("%s declares no role %q", c.Caller.Name, c.Role)
		}
		held = scope.Intersect(role, c.Audience.ResourceKinds)
		stage("role", "roles["+c.Role+"].scopes", held, roleErr)
	}

	switch {
	case !declared:
		ceilingErr = domain.Missing("%s declares no binding %q", c.Caller.Name, c.Binding)
	case b.Audience != c.Audience.Principal:
		ceilingErr = domain.Refuse("binding %q of %s is addressed to %s, not %s", c.Binding, c.Caller.Name, b.Audience, c.Audience.Principal)
	default:
		ceilingErr = ValidateModule(c.Caller)
	}
	carried := held
	if c.Role != "" {
		carried = Through(held, b, operation, c.Audience)
	}
	stage("ceiling", "bindings["+c.Binding+"]."+operation, carried, ceilingErr)

	field := "principals[" + c.Caller.Principal + "].operation_audiences[" + c.Binding + "]." + operation + "_scopes"
	switch {
	case c.EnvelopeUnread != "":
		links = append(links, Link{Name: "envelope", Verdict: Unread, Field: field,
			Reason: c.EnvelopeUnread + "; the links below are judged on the binding as declared, before any envelope narrows it"})
	case c.Envelope == nil:
		carried = nil
		stage("envelope", field, nil, domain.Refuse("the envelope allows %s no operation binding %q, so the host registers none and every call through it is refused", c.Caller.Principal, c.Binding))
	default:
		granted, err := Granted(b, *c.Envelope)
		if c.Role != "" {
			carried = Through(held, granted, operation, c.Audience)
		} else {
			carried = granted.HeadlessScopes
		}
		if withheld := Withheld(b, granted); err == nil && len(withheld) > 0 {
			err = domain.Refuse("the envelope withholds what binding %q asks for (%s): the host drops it without a record", c.Binding, strings.Join(withheld, ", "))
			if decidable && AdmitPolicy(c.Audience.Principal, c.Method, policy, carried) == nil {
				// Withheld, and not what this method needs: say it, refuse nothing.
				links = append(links, Link{Name: "envelope", Verdict: Admitted, Field: field, Value: describe(carried), Reason: err.Error()})
				break
			}
		}
		stage("envelope", field, carried, err)
	}

	received := ModuleRoleAt(c.Caller, c.Installation, c.Audience, carried)
	if c.Role == "" {
		received, _ = HeadlessAt(c.Caller, c.Installation, c.Audience, carried)
	}
	delivered := Link{Name: "policy", Verdict: Admitted, Field: "methods[" + c.Method + "]", Value: policyText(policy, served)}
	if err := AdmitMethod(c.Audience, c.Method, received); err != nil {
		delivered.Verdict, delivered.Reason = Refused, err.Error()
	}
	links = append(links, delivered)
	links = append(links, Copies(policy, served, c.Statements)...)
	return append(links, ownerLink(c, policy, decidable, received))
}

// Copies holds every other written copy of a method's policy to applied, the
// one a hop applies (served is false when it lists no such method): a copy
// saying anything else is refused naming both values, and a copy that could
// not be read is unread. Two copies of one fact agree or one of them is not
// what decides the call; nothing here picks which.
func Copies(applied domain.MethodPolicy, served bool, copies []Statement) []Link {
	want := policyText(applied, served)
	links := make([]Link, 0, len(copies))
	for _, s := range copies {
		link := Link{Name: "policy copy", Verdict: Admitted, Field: s.Where, Value: policyText(s.Policy, s.Declared)}
		switch {
		case s.Unread != "":
			link.Verdict, link.Value, link.Reason = Unread, "", s.Unread
		case link.Value != want:
			link.Verdict = Refused
			link.Reason = fmt.Sprintf("it says %q and the policy it must equal says %q: one of the two is not what the hop applies", link.Value, want)
		}
		links = append(links, link)
	}
	return links
}

// ownerLink answers the one check a method policy cannot state: an audience
// that checks owners decides each resource in its handler, against the owner
// a scope selects. Declarations prove it only so far, and the link says how
// far.
func ownerLink(c Call, policy domain.MethodPolicy, decidable bool, received Scopes) Link {
	link := Link{Name: "owner", Verdict: Admitted, Field: "owner_aware", Value: describe(received)}
	switch {
	case !c.Audience.OwnerAware:
		link.Value = c.Audience.Name + " checks no resource owner"
	case !decidable:
		link.Verdict, link.Reason = Unproven, "no usable policy says which kinds the handler reads"
	case policy.AnyCheckedCaller:
		link.Verdict = Unproven
		link.Reason = fmt.Sprintf("%s checks owners and declares %s open to any checked caller: its handler decides each resource, and no declaration states what it asks of the call", c.Audience.Name, c.Method)
	default:
		selected := slices.DeleteFunc(slices.Clone(received), func(sc *basev0.WorkScopeV1) bool { return sc.GetResourceOwnerId() == "" })
		var absent, unselected []string
		for _, r := range policy.Requires {
			for _, action := range r.GetActions() {
				permission := r.GetResourceKind() + ":" + action
				switch {
				case !scope.HoldsAction(received, r.GetResourceKind(), action):
					absent = append(absent, permission)
				case !slices.Contains(c.Audience.SharedKinds, r.GetResourceKind()) && !scope.HoldsAction(selected, r.GetResourceKind(), action):
					unselected = append(unselected, permission)
				}
			}
		}
		switch {
		case len(absent) > 0:
			link.Verdict = Refused
			link.Reason = fmt.Sprintf("the call arrives without %s, so %s's handler has no scope to check an owner against", strings.Join(absent, ", "), c.Audience.Name)
		case len(unselected) > 0:
			link.Verdict = Unproven
			link.Reason = fmt.Sprintf("%s checks owners, and the call arrives holding %s selected to no installation's owner: what its handler lets such a scope reach is declared nowhere", c.Audience.Name, strings.Join(unselected, ", "))
		default:
			link.Reason = fmt.Sprintf("holds for what installation principal %s owns; a resource another owner holds is refused by %s's handler", c.Installation.PrincipalID, c.Audience.Name)
		}
	}
	return link
}

// First is the first link of a trace that is not Admitted, the one a person
// fixes first; ok is false when every link admits the call.
func First(links []Link) (Link, bool) {
	i := slices.IndexFunc(links, func(l Link) bool { return l.Verdict != Admitted })
	if i < 0 {
		return Link{}, false
	}
	return links[i], true
}

// Granted is binding asked as an envelope entry allowing allowed leaves it:
// per operation, only what both name, and a lookup only beside an invoke left
// standing. An entry for another audience, or one leaving nothing to invoke
// or to do headless, grants no binding at all. It is the host's narrowing of a
// delivered binding to its envelope, stated once for every reader.
func Granted(asked, allowed domain.Binding) (domain.Binding, error) {
	if allowed.Audience != asked.Audience {
		return domain.Binding{}, domain.Refuse("binding %q asks for audience %q and the envelope allows %q", asked.ID, asked.Audience, allowed.Audience)
	}
	out := domain.Binding{ID: asked.ID, Audience: asked.Audience,
		InvokeScopes:   scope.Intersect(asked.InvokeScopes, allowed.InvokeScopes),
		HeadlessScopes: scope.Intersect(asked.HeadlessScopes, allowed.HeadlessScopes)}
	if len(out.InvokeScopes) > 0 {
		out.LookupScopes = scope.Intersect(asked.LookupScopes, allowed.LookupScopes)
	}
	if len(out.InvokeScopes) == 0 && len(out.HeadlessScopes) == 0 {
		return out, domain.Refuse("the envelope allows binding %q none of what it asks to invoke or to do headless, so the host registers no such binding", asked.ID)
	}
	return out, nil
}

// Withheld spells, "<operation> <kind>:<action>", each action binding asked
// names that granted, the same binding after an envelope, no longer carries
// at all: what a host drops when it narrows. An envelope narrowing an action
// to named resources withholds nothing here; that is an author's act.
func Withheld(asked, granted domain.Binding) []string {
	var out []string
	for _, operation := range []string{"invoke", "headless", "lookup"} {
		wanted, _ := ScopesFor(asked, operation, "")
		kept, _ := ScopesFor(granted, operation, "")
		for _, sc := range scope.Normalize(wanted) {
			for _, action := range sc.GetActions() {
				if !scope.HoldsAction(kept, sc.GetResourceKind(), action) {
					out = append(out, operation+" "+sc.GetResourceKind()+":"+action)
				}
			}
		}
	}
	return out
}

// policyText spells a method policy as a person compares two copies of it.
func policyText(p domain.MethodPolicy, declared bool) string {
	switch {
	case !declared:
		return "not listed"
	case p.AnyCheckedCaller && len(p.Requires) == 0:
		return "any checked caller"
	}
	text := "requires " + describe(scope.Normalize(p.Requires))
	if p.AnyCheckedCaller {
		text += " and any checked caller"
	}
	return text
}
