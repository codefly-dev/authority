package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// signInChoice is presentation owned by the composing workspace, not a grant
// or a sign-in allowlist. IDs resolve only against the host's fixture people;
// the composition never supplies tokens, roles or organisations here.
type signInChoice struct {
	PersonID    string `json:"personId"`
	Description string `json:"description"`
	StartHere   bool   `json:"startHere,omitempty"`
}

func parseSignInChoices(value string) ([]signInChoice, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var choices []signInChoice
	dec := json.NewDecoder(strings.NewReader(value))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&choices); err != nil {
		return nil, fmt.Errorf("expected an array of fixture choices: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("expected a single array of fixture choices")
	}
	if len(choices) == 0 {
		return nil, fmt.Errorf("configured choices must name at least one fixture person; omit the key to show everyone")
	}
	seen := map[string]bool{}
	starts := 0
	for _, choice := range choices {
		if choice.PersonID == "" || strings.TrimSpace(choice.PersonID) != choice.PersonID {
			return nil, fmt.Errorf("each choice must name a nonblank fixture person ID without surrounding whitespace")
		}
		if seen[choice.PersonID] {
			return nil, fmt.Errorf("fixture person %q is selected more than once", choice.PersonID)
		}
		seen[choice.PersonID] = true
		if strings.TrimSpace(choice.Description) == "" || strings.ContainsAny(choice.Description, "\r\n") {
			return nil, fmt.Errorf("fixture person %q needs a one-line description", choice.PersonID)
		}
		if choice.StartHere {
			starts++
		}
	}
	if starts > 1 {
		return nil, fmt.Errorf("only one fixture person may be marked Start here")
	}
	return choices, nil
}

func selectSignInPeople(people []fixturePerson, choices []signInChoice) ([]fixturePerson, error) {
	if choices == nil {
		return people, nil
	}
	byID := map[string]fixturePerson{}
	for _, person := range people {
		if _, exists := byID[person.PersonID]; exists {
			return nil, fmt.Errorf("the authority lists ambiguous fixture person ID %q", person.PersonID)
		}
		byID[person.PersonID] = person
	}
	selected := make([]fixturePerson, 0, len(choices))
	for _, choice := range choices {
		person, exists := byID[choice.PersonID]
		if !exists {
			return nil, fmt.Errorf("fixture person %q is not listed by this authority", choice.PersonID)
		}
		person.Description, person.StartHere = choice.Description, choice.StartHere
		selected = append(selected, person)
	}
	return selected, nil
}
