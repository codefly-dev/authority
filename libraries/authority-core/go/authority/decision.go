package authority

import (
	"cmp"
	"context"
	"errors"
	"fmt"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

// DecisionKind names what was asked of the authority.
type DecisionKind string

// The decisions a host is told of (Config.Decisions).
const (
	// A person's capability on their own session (IssueForPerson).
	DecisionIssuePerson DecisionKind = "issue.person"
	// A person's capability for a call their page makes (IssueForPage): one
	// decision, whichever steps it took.
	DecisionIssuePage DecisionKind = "issue.page"
	// A module's own headless capability (IssueForWorkload).
	DecisionIssueWorkload DecisionKind = "issue.workload"
	// An installation acting for itself (IssueForInstallation).
	DecisionIssueInstallation DecisionKind = "issue.installation"
	// One more hop on a presented capability (IssueChild).
	DecisionIssueChild DecisionKind = "issue.child"
	// A module issuing from a person's delegation (IssueForDelegation).
	DecisionIssueDelegation DecisionKind = "issue.delegation"
	// A client issuing from a person's delegation (IssueForClientDelegation).
	DecisionIssueClientDelegation DecisionKind = "issue.client_delegation"
	// A capability checked for an audience, and for a method when one is
	// named (CheckMethod).
	DecisionCheck DecisionKind = "check"
	// Which resources a checked capability covers (ListResources).
	DecisionListResources DecisionKind = "resources.list"
)

// Outcome is how a decision ended.
type Outcome string

// A decision admits what was asked or refuses it.
const (
	Admitted Outcome = "admitted"
	Refused  Outcome = "refused"
)

// The codes of a refused decision: a refusal's own code (domain.Code), the
// two a capability that does not verify adds, and the authority failing to
// decide at all.
const (
	CodeDenied          = "denied"
	CodeNotFound        = "not_found"
	CodeInvalid         = "invalid"
	CodePrecondition    = "precondition"
	CodeUnauthenticated = "unauthenticated"
	CodeRevoked         = "revoked"
	// CodeInternal: no decision was reached (the store failed, the context
	// ended). The caller was given nothing, so it is reported as refused.
	CodeInternal = "internal"
)

// Decision is one decision of the authority, admitted or refused, as a host
// records it. It carries whatever was known when the decision ended: an
// admitted one what the signed or verified capability names, a refused one
// what the ask named and what the authority had resolved by then, so a
// refused ask still says where and who.
type Decision struct {
	Kind    DecisionKind
	Outcome Outcome
	// Advisory marks a check that decided a method without enforcing it
	// (CheckMethod's advisory): Outcome is the method's, and the caller was
	// answered the verified capability with the refusal beside it.
	Advisory bool
	// Code and Reason are a refusal's; both empty when admitted.
	Code, Reason string
	// Organization is where the work is; Owner whose authority it runs on (a
	// person, a module's principal, an installation's principal); Actor who
	// asked or acts (the person, the module whose workload asked, the last
	// hop of a checked capability).
	Organization, Owner, Actor string
	// Audience is the principal the capability is addressed to (as asked,
	// when refused before it was resolved); Binding and Operation what the
	// ask exercised, Binding as the ask named it, or the capability's own
	// operation binding when a check reads it.
	Audience, Binding, Operation string
	// Method is the method a check named.
	Method string
	// Installation is the installation the capability is sealed to, or the
	// one an installation's ask named; Task the capability's task;
	// Delegation the delegation an issue was made from.
	Installation, Task, Delegation string
	// Claimed says the organization, owner, actor, installation and task were
	// read from a capability that did not verify: what it claims, proven by
	// nothing. A host files such a row under no organization's own journal
	// on its word.
	Claimed bool
}

// AdmittedCheck is whether d is a check or a resource listing that was
// admitted: what every served call makes, and what a host that records
// refusals and issuances skips first.
func (d Decision) AdmittedCheck() bool {
	return d.Outcome == Admitted && (d.Kind == DecisionCheck || d.Kind == DecisionListResources)
}

// of reads what a capability names: the one signed for an admitted issue,
// the one a check verified.
func (d *Decision) of(wc *basev0.WorkContextV1) {
	d.Organization = wc.GetOrganizationId()
	if d.Organization == "" {
		d.Organization = wc.GetTenantId()
	}
	d.Owner, d.Task, d.Installation = wc.GetOwnerPrincipalId(), wc.GetTaskId(), wc.GetSeal().GetInstallationId()
	d.Actor = d.Owner
	if chain := wc.GetActorChain(); len(chain) > 0 {
		d.Actor = chain[len(chain)-1].GetPrincipalId()
	}
	if d.Binding == "" {
		d.Binding = wc.GetOperationBinding().GetBindingId()
	}
}

// resolved fills where, whose and for which audience a refused ask is, once
// the authority read each, and never over what the ask itself named.
func (d *Decision) resolved(organization, owner, audience string) {
	d.Organization = cmp.Or(d.Organization, organization)
	d.Owner = cmp.Or(d.Owner, owner)
	d.Audience = cmp.Or(d.Audience, audience)
}

// onParent is a hop whose parent verified: the work is its owner's, in its
// organization, on its task, whatever the hop is then refused for.
func (d *Decision) onParent(parent *basev0.WorkContextV1) {
	d.Organization = parent.GetOrganizationId()
	if d.Organization == "" {
		d.Organization = parent.GetTenantId()
	}
	d.Owner, d.Task = parent.GetOwnerPrincipalId(), parent.GetTaskId()
}

// claimedBy is a refused hop whose parent never verified: when the parent
// still reads as a capability, what it claims, marked as that.
func (d *Decision) claimedBy(parent string) {
	if d.Owner != "" {
		return
	}
	if decoded, err := workcontext.Decode(parent); err == nil {
		d.onParent(decoded.Context())
		d.Claimed = true
	}
}

// issued tells the host an issuance's decision and answers the caller: the
// capability, unless it was refused or the host could not record it.
func (s *Service) issued(ctx context.Context, d *Decision, out Issued, err error) (Issued, error) {
	if err == nil && s.cfg.CheckSession != nil && out.Context.GetOwnerPrincipalKind() == "human" {
		if err = s.cfg.CheckSession(ctx, rootSession(out.Context)); err != nil {
			out = Issued{}
		}
	}

	if s.cfg.Decisions == nil {
		return out, err
	}
	if err == nil {
		d.of(out.Context)
		d.Audience = out.Context.GetAudience()
	}
	if failed := s.tell(ctx, d, err); failed != nil {
		return Issued{}, failed
	}
	return out, err
}

// checked tells the host a check's decision, naming what the capability
// proved when it verified and what it claims when it did not. It answers
// only the hook's failure.
func (s *Service) checked(ctx context.Context, d *Decision, token string, proven *workcontext.Verified, refusal error) error {
	if proven != nil {
		d.of(proven.Context())
	} else if decoded, err := workcontext.Decode(token); err == nil {
		d.of(decoded.Context())
		d.Claimed = true
	}
	return s.tell(ctx, d, refusal)
}

// tell hands the host one decision, refused when refusal is set. It answers
// nil when the host took it: the caller's own answer stands. When the host
// did not, it answers the error that fails the operation, which is still the
// refusal (its code, its sentinel) when there was one.
func (s *Service) tell(ctx context.Context, d *Decision, refusal error) error {
	d.Outcome = Admitted
	if refusal != nil {
		d.Outcome, d.Code, d.Reason = Refused, decisionCode(refusal), refusal.Error()
	}
	err := s.cfg.Decisions(ctx, *d)
	switch {
	case err == nil:
		return nil
	case refusal == nil:
		return fmt.Errorf("authority: the host did not record the decision, so nothing is admitted on it: %w", err)
	default:
		return fmt.Errorf("%w (the host did not record this refusal: %w)", refusal, err)
	}
}

// decisionCode classifies what ended a decision.
func decisionCode(err error) string {
	if code, ok := domain.CodeOf(err); ok {
		switch code {
		case domain.NotFound:
			return CodeNotFound
		case domain.Invalid:
			return CodeInvalid
		case domain.Precondition:
			return CodePrecondition
		default:
			return CodeDenied
		}
	}
	switch {
	case errors.Is(err, workcontext.ErrNoBinding):
		return CodeNotFound
	case errors.Is(err, workcontext.ErrRevoked), errors.Is(err, workcontext.ErrNoSeal):
		return CodeRevoked
	case errors.Is(err, workcontext.ErrInvalid), errors.Is(err, workcontext.ErrNotACoreToken), errors.Is(err, workcontext.ErrReplayed):
		return CodeUnauthenticated
	default:
		return CodeInternal
	}
}
