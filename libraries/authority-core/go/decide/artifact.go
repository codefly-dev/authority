package decide

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The artifact interface (codefly.dev/artifact): a person's consent to an exact
// authored artifact a module runs, for one installation, under one policy. A
// policy is a resource kind the module serves, nothing more: approving and
// revoking need its activate action, held by the person present; a run needs
// its run action, which a delegated context may carry. What a person may
// approve is what their roles grant at the module; there is no policy
// document and no second permission table, administrator or not.
const (
	ArtifactActivate = "activate"
	ArtifactRun      = "run"
)

// ArtifactIdentity is an artifact's canonical identity, as the module's
// compiler exports it (host.artifact.v1.Identity).
type ArtifactIdentity struct {
	Schema, Source   string
	Subject          []byte
	Contracts        []ArtifactContract
	ExpectedRevision int64
}

// ArtifactContract is one contract the artifact is compiled against.
type ArtifactContract struct{ Kind, Name, Digest string }

// ArtifactCaller is who asks: the module its workload credential proves, and
// the verified parent it presents.
type ArtifactCaller struct {
	Module domain.Module
	// The parent's audience, organization, owner kind and effective scopes,
	// and whether a module acts between its owner and the asking module.
	Audience, Tenant, OwnerKind string
	Delegated                   bool
	Held                        Scopes
}

// Namespace is the source an installation's authored artifacts belong to:
// "<organization>.<target>". The host names it; no module chooses it.
func Namespace(inst domain.Installation) string { return inst.Organization + "." + inst.Target }

// Artifact decides whether caller may take action ("activate" to approve or
// revoke, "run" to authorize) on policy at the installation the request
// names (inst, when found). identity is nil for a revoke. The answer is nil
// or a named refusal: Malformed for a request missing what it must name,
// Refuse for everything else, so a foreign installation and a missing one
// read alike.
func Artifact(caller ArtifactCaller, inst domain.Installation, found bool, requested, policy, action string, identity *ArtifactIdentity) error {
	switch {
	case action != ArtifactActivate && action != ArtifactRun:
		return domain.Malformed("an artifact decision is %q or %q, not %q", ArtifactActivate, ArtifactRun, action)
	case policy == "":
		return domain.Malformed("an artifact request names its policy, a resource kind of the module")
	case identity != nil && (identity.Schema == "" || identity.Source == "" || len(identity.Subject) == 0):
		return domain.Malformed("an artifact names its schema, source and subject")
	case caller.Audience != caller.Module.Principal:
		return domain.Refuse("%s asks about a context addressed to %s", caller.Module.Name, caller.Audience)
	case action == ArtifactActivate && (caller.OwnerKind != "human" || caller.Delegated):
		return domain.Refuse("consent to an artifact is given by a person present, not through a module acting for them")
	case !found || inst.Organization != caller.Tenant:
		return ForeignInstallation(requested, caller.Tenant)
	case inst.Target != caller.Module.Name || inst.Status != domain.Active:
		return domain.Refuse("installation %s is not %s's active installation at %s", requested, caller.Module.Name, caller.Tenant)
	case !slices.ContainsFunc(caller.Module.ResourceKinds, func(k *basev0.WorkScopeV1) bool { return k.GetResourceKind() == policy }):
		return domain.Refuse("%s is not an artifact policy of %s: it serves no such kind", policy, caller.Module.Name)
	}
	// The identity establishes no resource id of the policy kind, so the
	// parent holds the action on the whole kind, for the installation's owner
	// (a module installation has none, so an owner-unrestricted scope).
	needed := Scopes{{ResourceKind: policy, Actions: []string{action}, ResourceOwnerId: inst.PrincipalID}}
	if !scope.Attenuates(needed, caller.Held) {
		return domain.Refuse("the parent does not hold %s:%s on the whole kind at %s; an artifact identity names no resource of the policy", policy, action, caller.Module.Name)
	}
	if identity != nil && identity.Source != Namespace(inst) {
		return domain.Refuse("artifact source %q is not installation %s's namespace %q", identity.Source, inst.ID, Namespace(inst))
	}
	return nil
}

// ArtifactDigest is the approval's digest, "sha256:<hex>" of the identity's
// deterministic protobuf encoding (host.artifact.v1.Identity), written here
// field by field so a host links no second copy of the generated package.
func ArtifactDigest(id ArtifactIdentity) string {
	var b []byte
	b = appendString(b, 1, id.Schema)
	b = appendString(b, 2, id.Source)
	if len(id.Subject) > 0 {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendBytes(b, id.Subject)
	}
	for _, c := range id.Contracts {
		var m []byte
		m = appendString(m, 1, c.Kind)
		m = appendString(m, 2, c.Name)
		m = appendString(m, 3, c.Digest)
		b = protowire.AppendTag(b, 4, protowire.BytesType)
		b = protowire.AppendBytes(b, m)
	}
	if id.ExpectedRevision != 0 {
		b = protowire.AppendTag(b, 5, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(id.ExpectedRevision))
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func appendString(b []byte, field protowire.Number, s string) []byte {
	if s == "" {
		return b
	}
	b = protowire.AppendTag(b, field, protowire.BytesType)
	return protowire.AppendString(b, s)
}
