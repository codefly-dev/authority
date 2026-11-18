package solutionhost

// The host's delivery surface, as the host serves and reads it. A render that
// delivers to this host addresses these routes, mounts the trust anchor at this
// path and hands the host these configuration keys; none of them is a workspace
// value, because a composition that could name them could point the host's
// verifier at a policy it wrote itself. They are declared here, with the host,
// so a tool that renders for the host knows them only through this library.
const (
	// ManifestDeliveryPath is the route a delivery carrier POSTs a signed
	// module manifest to, relative to the host's delivery endpoint.
	ManifestDeliveryPath = "/platform/_delivery/manifest"
	// EnvelopeDeliveryPath is the route a delivery carrier POSTs the module
	// envelope to.
	EnvelopeDeliveryPath = "/platform/_delivery/envelope"
	// AppliedDeliveryPath prefixes the route that answers what the host has
	// applied for one binding (the binding, path-escaped, follows it).
	AppliedDeliveryPath = "/platform/_delivery/applied/"

	// HostedTrustAnchorPath is where a deployed host reads its trust anchor
	// (verification_policy.json). The host refuses to relocate it from inside
	// a pod, and the platform mounts its `<component>-delivery-trust`
	// ConfigMap there.
	HostedTrustAnchorPath = "/etc/obin/delivery-trust"

	// HostCoordinateKey, HostOwnershipDomainsKey and HostTrustPolicyKey are
	// the configuration keys a host reads to answer for a coordinate: the
	// coordinate itself, the ownership domains it accepts a binding under, and
	// how it checks a delivered carrier.
	HostCoordinateKey       = "SOLUTION_HOST_COORDINATE"
	HostOwnershipDomainsKey = "SOLUTION_HOST_OWNERSHIP_DOMAINS"
	HostTrustPolicyKey      = "SOLUTION_HOST_TRUST_POLICY"
	// HostTrustPolicyKeys is HostTrustPolicyKey's one value: pinned keys.
	HostTrustPolicyKeys = "keys"
	// LocalTrustAnchorKey names the directory a local host reads its trust
	// anchor from when a native run stands it up.
	LocalTrustAnchorKey = "SOLUTION_HOST_LOCAL_TRUST_ANCHOR"
)
