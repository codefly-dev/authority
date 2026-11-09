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
// grants there. r.Binding names the binding when target declares more than
// one to the audience. When target declares none, the audience is an edge
// the page reaches on the person's own session, and their own access there
// decides, as IssueForPerson answers.
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
		binding, err = pageBinding(page, audience.Principal, r.Binding)
		return err
	})
	if err != nil {
		return Issued{}, err
	}
	if binding == "" {
		r.Binding = ""
		return s.IssueForPerson(ctx, who, r)
	}
	root, err := s.IssueForPerson(ctx, who, IssueRequest{Audience: page.Principal, Organization: r.Organization, TTL: r.TTL})
	if err != nil {
		return Issued{}, err
	}
	return s.IssueChild(ctx, root.Token, Workload{Module: page.Name}, IssueRequest{Audience: r.Audience, Binding: binding, Operation: r.Operation, Scopes: r.Scopes, TTL: r.TTL})
}

// pageBinding is the binding of page a person's call at audience goes
// through: the one page declares to it for a person (invoke or lookup), the
// one named among them, or none when it declares none. Two, with none named,
// is refused rather than chosen.
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
	return "", nil
}
