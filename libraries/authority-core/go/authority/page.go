package authority

import (
	"context"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// IssueForPage is the person's capability at r.Audience for a call the page
// of target (a solution or a module page) makes on the host's module edge:
// one rule for every page, the one its backend is held to.
//
// When target declares a binding to the audience, the capability is issued
// through it, exactly as the target's own workload would hop with the
// person's Work Context: the person's capability at target (their roles
// there), then target's hop over the binding, so the person holds at the
// audience their role on target cut to the binding, and nothing of their own
// grants there. That hop's actor is of kind decide.PageActor: the person
// present on the target's page, which consent in person admits as it admits
// no other actor (decide.Artifact). Only this path takes it; a host serves it
// to its module edge alone. r.Binding names the binding when target declares
// more than one to the audience. A call to target itself is the person's
// capability there, their roles on it (IssueForPerson). A call to any other
// module target declares no person-usable binding to (invoke or lookup) is
// refused, by name: a page reaches a module only through a binding its
// target declares, never on the person's own access (RBAC-3).
func (s *Service) IssueForPage(ctx context.Context, who Person, target string, r IssueRequest) (Issued, error) {
	var page domain.Module
	var binding string
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		if page, err = tx.ModuleNamed(target); err != nil {
			return notFound(err)
		}
		audience, err := tx.Module(r.Audience)
		if err != nil {
			return notFound(err)
		}
		if audience.Principal == page.Principal {
			return nil
		}
		binding, err = pageBinding(page, audience.Principal, r.Binding)
		return err
	})
	if err != nil {
		return Issued{}, err
	}
	if binding == "" {
		// The page's own target: the person's roles there.
		r.Binding = ""
		return s.IssueForPerson(ctx, who, r)
	}
	root, err := s.IssueForPerson(ctx, who, IssueRequest{Audience: page.Principal, Organization: r.Organization, TTL: r.TTL})
	if err != nil {
		return Issued{}, err
	}
	return s.IssueChild(ctx, root.Token, Workload{Module: page.Name}, IssueRequest{Audience: r.Audience, Binding: binding, Operation: r.Operation, Scopes: r.Scopes, TTL: r.TTL, page: true})
}

// pageBinding is the binding of page a person's call at audience goes
// through: the one page declares to it for a person (invoke or lookup), or
// the one named among them. None declared, a name page does not declare, or
// two with none named is refused rather than chosen.
func pageBinding(page domain.Module, audience, named string) (string, error) {
	var declared []string
	for id, b := range page.Bindings {
		if b.Audience == audience && (len(b.InvokeScopes) > 0 || len(b.LookupScopes) > 0) {
			declared = append(declared, id)
		}
	}
	slices.Sort(declared)
	switch {
	case named != "" && slices.Contains(declared, named):
		return named, nil
	case named != "" && len(declared) > 0:
		return "", domain.Missing("%s declares no binding %q to %s", page.Name, named, audience)
	case len(declared) > 1:
		return "", domain.Refuse("%s declares %d bindings to %s (%v); the call names the one it goes through", page.Name, len(declared), audience, declared)
	case len(declared) == 1:
		return declared[0], nil
	}
	return "", domain.Refuse("%s declares no binding to %s: a page reaches a module only through a binding its target declares (invoke or lookup), never on the person's own access", page.Name, audience)
}
