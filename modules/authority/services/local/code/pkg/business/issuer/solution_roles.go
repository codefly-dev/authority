package issuer

import (
	"context"
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

// AttachResource delegates ownership decisions to the shared authority core.
func (i *Issuer) AttachResource(ctx context.Context, token, credential, kind, id string) (string, error) {
	w, err := i.workload(ctx, credential, "an attachment is asked by the module serving the kind")
	if err != nil {
		return "", err
	}
	out, err := i.svc.AttachResource(ctx, authority.AttachmentRequest{Token: token, Store: w, Kind: kind, ResourceID: id})
	return out, classify(err)
}

// DetachResource delegates deletion to the shared authority core.
func (i *Issuer) DetachResource(ctx context.Context, credential, org, kind, id string) (string, error) {
	w, err := i.workload(ctx, credential, "a detachment is asked by the module serving the kind")
	if err != nil {
		return "", err
	}
	out, err := i.svc.DetachResource(ctx, w, org, kind, id)
	return out, classify(err)
}
