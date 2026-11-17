package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
)

// THE EDGE ROUTES WHAT A MODULE DECLARES.
//
// Which procedures a module's Connect face serves is read from edge-routes, a
// workspace-configuration group Codefly generates for the service declaring
// it (cli, pkg/orchestration/edge_routes.go): per module the edge mounts that
// is published through the hop, every procedure the module's own published
// contracts declare on a Connect listener. It is read from the API catalog
// the hop's routes and a delivery to the authority are read from, so the edge
// routes a procedure exactly when its module publishes it, and no composition
// lists services (`<MODULE>_RPC`, read by nobody now).
//
// The catalog does not say which service a page calls and which only another
// module does, so the document holds both and the edge routes both: the hop
// behind the face decides who is admitted, as it does for every caller. A
// foreign method (another module's protocol, served to that module) is not in
// it. The document carries no address: where a module's face is stays the
// composition's `<MODULE>_CONNECT`.
const (
	edgeRoutesGroup  = "edge-routes"
	edgeRoutesKey    = "ROUTES"
	edgeRoutesSchema = "codefly.dev/edge-routes/v1"
)

// edgeRoutes is the generated document.
type edgeRoutes struct {
	Schema  string `json:"schema"`
	Modules []struct {
		// Audience is the module's principal, the name it is mounted under.
		Audience string `json:"audience"`
		// Procedures are full protobuf procedures, /package.Service/Method.
		Procedures []string `json:"procedures"`
	} `json:"modules"`
}

// publishedProcedures decodes the generated document into the procedures each
// module publishes. An empty value is no document: this edge runs under a
// Codefly that generates none, and it does not start (mount says why).
func publishedProcedures(raw string) (map[string][]string, error) {
	var routes edgeRoutes
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&routes); err != nil {
		return nil, fmt.Errorf("%s/%s: %w", edgeRoutesGroup, edgeRoutesKey, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%s/%s: trailing JSON", edgeRoutesGroup, edgeRoutesKey)
	}
	if routes.Schema != edgeRoutesSchema {
		return nil, fmt.Errorf("%s/%s: expected schema %s, read %q", edgeRoutesGroup, edgeRoutesKey, edgeRoutesSchema, routes.Schema)
	}
	published := map[string][]string{}
	for _, module := range routes.Modules {
		if module.Audience == "" {
			return nil, fmt.Errorf("%s/%s: a module with no audience", edgeRoutesGroup, edgeRoutesKey)
		}
		if _, twice := published[module.Audience]; twice {
			return nil, fmt.Errorf("%s/%s: module %s is listed twice", edgeRoutesGroup, edgeRoutesKey, module.Audience)
		}
		for _, procedure := range module.Procedures {
			if !pageProcedure.MatchString(procedure) {
				return nil, fmt.Errorf("%s/%s: %q of module %s is not a procedure (/package.Service/Method)", edgeRoutesGroup, edgeRoutesKey, procedure, module.Audience)
			}
		}
		published[module.Audience] = slices.Clone(module.Procedures)
	}
	return published, nil
}

// mount is the modules the edge routes to: the composition's edge group names
// them (MODULES) and, per module, where its REST face (<MODULE>_REST) and its
// Connect face (<MODULE>_CONNECT) are; routes is the generated edge-routes
// document, which says what each Connect face serves.
func mount(value func(key string) string, routes string) (map[string]Module, error) {
	names := list(value("MODULES"))
	if strings.TrimSpace(routes) == "" {
		var typed []string
		for _, name := range names {
			if key := prefixOf(name) + "RPC"; value(key) != "" {
				typed = append(typed, key)
			}
		}
		reason := fmt.Sprintf("edge: %s/%s is empty: this edge routes the procedures Codefly generates from each module's published API catalog, and the Codefly that started this run generated none. Run it with a Codefly that generates %s",
			edgeRoutesGroup, edgeRoutesKey, edgeRoutesGroup)
		if len(typed) > 0 {
			reason += fmt.Sprintf(" (%s is no longer read, and can be deleted from the composition's edge group)", strings.Join(typed, ", "))
		}
		return nil, fmt.Errorf("%s", reason)
	}
	published, err := publishedProcedures(routes)
	if err != nil {
		return nil, fmt.Errorf("edge: %w", err)
	}
	modules, publisher := map[string]Module{}, map[string]string{}
	for _, name := range names {
		prefix := prefixOf(name)
		m := Module{Name: name}
		if m.REST, err = baseURL(value(prefix + "REST")); err != nil {
			return nil, fmt.Errorf("edge: %sREST: %w", prefix, err)
		}
		if m.Connect, err = baseURL(value(prefix + "CONNECT")); err != nil {
			return nil, fmt.Errorf("edge: %sCONNECT: %w", prefix, err)
		}
		if m.REST == nil && m.Connect == nil {
			return nil, fmt.Errorf("edge: the composition names neither a REST nor a Connect face for %s", name)
		}
		procedures := published[name]
		switch {
		case m.Connect != nil && len(procedures) == 0:
			return nil, fmt.Errorf("edge: %sCONNECT names a Connect face for %s, but %s publishes no procedure on a Connect listener through the hop: name it in hop/MODULES and publish its API catalog, or remove %sCONNECT",
				prefix, name, name, prefix)
		case m.Connect == nil && len(procedures) > 0:
			// The composition's choice, said aloud: nothing of it is routed.
			log.Printf("edge: %s publishes %d procedure(s) over Connect, none routed: the composition names no %sCONNECT", name, len(procedures), prefix)
		case m.Connect != nil:
			for _, procedure := range procedures {
				if other, taken := publisher[procedure]; taken {
					return nil, fmt.Errorf("edge: %s is published by both %s and %s, and a page's call names no module: the edge cannot tell which one serves it", procedure, other, name)
				}
				publisher[procedure] = name
			}
			m.Procedures = procedures
		}
		modules[name] = m
	}
	return modules, nil
}

// prefixOf is the prefix of a module's keys in the edge group.
func prefixOf(module string) string {
	return strings.ToUpper(strings.ReplaceAll(module, "-", "_")) + "_"
}
