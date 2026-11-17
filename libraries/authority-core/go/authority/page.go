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
// more than one to the audience. The page calling its own target's module is
// the person's own ask there, decided by their role on target as
// IssueForPerson answers. To any other audience target declares no binding
// to, the call is refused: being signed in on a page is not a way in to a
// module, the page's binding is, and a person's own session holds nothing at
// a module.
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
		binding, err = pageBinding(page, audience, r.Binding)
		return err
	})
	if err != nil {
		return Issued{}, err
	}
	if binding == "" {
		// The page's own module: the person at target, on their role there.
		r.Binding = ""
		return s.IssueForPerson(ctx, who, r)
	}
	root, err := s.IssueForPerson(ctx, who, IssueRequest{Audience: page.Principal, Organization: r.Organization, TTL: r.TTL, page: true})
	if err != nil {
		return Issued{}, err
	}
	return s.IssueChild(ctx, root.Token, Workload{Module: page.Name}, IssueRequest{Audience: r.Audience, Binding: binding, Operation: r.Operation, Scopes: r.Scopes, TTL: r.TTL, page: true})
}

// pageBinding is the binding of page a person's call at audience goes
// through: the one page declares to it for a person (invoke or lookup), or
// the one named among them. Two, with none named, is refused rather than
// chosen; none, or a named one page does not declare to audience, is refused:
// page reaches audience through a binding or not at all. Its own module needs
// none and answers "": that call is the person's at page itself.
func pageBinding(page, audience domain.Module, named string) (string, error) {
	var declared []string
	for id, b := range page.Bindings {
		if b.Audience == audience.Principal && (len(b.InvokeScopes) > 0 || len(b.LookupScopes) > 0) {
			declared = append(declared, id)
		}
	}
	slices.Sort(declared)
	switch {
	case len(declared) == 0 && audience.Name == page.Name:
		return "", nil
	case len(declared) == 0:
		return "", domain.Refuse("%s declares no binding to %s, so its page reaches nothing there: a person reaches a module through the binding of an installation whose role they hold", page.Name, audience.Name)
	case named != "" && slices.Contains(declared, named):
		return named, nil
	case named != "":
		return "", domain.Missing("%s declares no binding %q to %s", page.Name, named, audience.Name)
	case len(declared) > 1:
		return "", domain.Refuse("%s declares %d bindings to %s (%v); the call names the one it goes through", page.Name, len(declared), audience.Name, declared)
	}
	return declared[0], nil
}
