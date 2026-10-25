package conformance

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// refused checks the public code and named reason, logging the actual reason
// verbatim so the host comparison can report evidence without tokens.
func refused(t *testing.T, err error, code codes.Code, reason string) {
	t.Helper()
	message := status.Convert(err).Message()
	if status.Code(err) != code || !strings.Contains(message, reason) || (code != codes.OK && message == "") {
		t.Fatalf("want %s with reason %q; got %v", code, reason, err)
	}
	if err != nil {
		t.Logf("refusal: %s: %s", code, message)
	}
}

func (c *client) sessionDisplayNames(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("Current names the person and organization for display", func(t *testing.T) {
		descriptor, err := c.files.FindDescriptorByName("host.session.v1.Session")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"person_display_name", "organization_display_name"} {
			if descriptor.(protoreflect.MessageDescriptor).Fields().ByName(protoreflect.Name(name)) == nil {
				t.Skip("pending interface addition: host.session.v1.Session needs person_display_name = 7 and organization_display_name = 8")
			}
		}
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		current := c.must(t, as(ctx, sess), "host.session.v1.SessionService", "Current", map[string]any{})
		for _, name := range []string{"person_display_name", "organization_display_name"} {
			if str(current, name) == "" {
				t.Fatalf("Current returned no %s", name)
			}
		}
		if str(current, "person_id") != str(sess, "person_id") || str(current, "organization_id") != f.Organization {
			t.Fatal("Current changed person or organization")
		}
	})
}
