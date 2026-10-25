package delivery

import (
	"fmt"
	"regexp"
)

var permissionName = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

// ValidatePermission checks the vocabulary of one declared permission. Wildcard
// fixture grants are not authored method requirements.
func ValidatePermission(kind, action string) error {
	if !permissionName.MatchString(kind) || !permissionName.MatchString(action) {
		return fmt.Errorf("invalid permission %q:%q: expected lowercase kind and action", kind, action)
	}
	return nil
}

// ValidateMethodPolicy is shared by offline preflight and delivered state.
// Local adoption may retain absent policy for named diagnostics; deployment
// requires an explicit policy. Contradictory or malformed policy is never valid.
func ValidateMethodPolicy(method string, anyChecked bool, requires map[string][]string, requireDeclaration bool) error {
	if method == "" {
		return fmt.Errorf("method policy has no method")
	}
	if anyChecked && len(requires) > 0 {
		return fmt.Errorf("%s declares both requirements and any_checked_caller", method)
	}
	if !anyChecked && len(requires) == 0 && requireDeclaration {
		return fmt.Errorf("%s declares no permission policy", method)
	}
	for kind, actions := range requires {
		if len(actions) == 0 {
			return fmt.Errorf("%s: %s declares no actions", method, kind)
		}
		for _, action := range actions {
			if err := ValidatePermission(kind, action); err != nil {
				return fmt.Errorf("%s: %w", method, err)
			}
		}
	}
	return nil
}
