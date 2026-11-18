package solutionhost

import (
	"reflect"
	"strings"
	"testing"
)

// The authored half is Frontend minus exactly the generated field, so a field
// added to the block is classified here — authored, and the standalone file
// accepts it, or generated, and the file refuses it — rather than drifting
// into one half by omission.
func TestTheAuthoredHalfIsTheFrontendMinusItsGeneratedFields(t *testing.T) {
	generated := map[string]bool{"payload": true}
	yamlName := func(field reflect.StructField) string {
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		return name
	}
	authored := map[string]reflect.Type{}
	for _, field := range reflect.VisibleFields(reflect.TypeOf(authoredFrontend{})) {
		authored[yamlName(field)] = field.Type
	}
	for _, field := range reflect.VisibleFields(reflect.TypeOf(Frontend{})) {
		name := yamlName(field)
		if generated[name] {
			if _, present := authored[name]; present {
				t.Errorf("%s is generated and must not be in the authored half", name)
			}
			continue
		}
		if authored[name] != field.Type {
			t.Errorf("%s is authored and must be in the authored half as a %s", name, field.Type)
		}
		delete(authored, name)
	}
	for name := range authored {
		t.Errorf("%s is in the authored half but not in Frontend", name)
	}
}
