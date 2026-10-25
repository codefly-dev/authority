package delivery

import "testing"

func TestPolicyValidityDoesNotDependOnRuntimeWarningMode(t *testing.T) {
	for _, local := range []bool{false, true} {
		if err := ValidateMethodPolicy("/api/Read", true, map[string][]string{"entry": {"read"}}, !local); err == nil {
			t.Fatal("contradictory policy accepted")
		}
		if err := ValidateMethodPolicy("/api/Read", false, map[string][]string{"entry": {"*"}}, !local); err == nil {
			t.Fatal("wildcard requirement accepted")
		}
		if err := ValidateMethodPolicy("/api/Read", false, map[string][]string{"entry": {"read"}}, !local); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateMethodPolicy("/api/Missing", false, nil, true); err == nil {
		t.Fatal("missing deployment policy accepted")
	}
	if err := ValidateMethodPolicy("/api/Missing", false, nil, false); err != nil {
		t.Fatal("local missing policy must remain diagnosable")
	}
}
