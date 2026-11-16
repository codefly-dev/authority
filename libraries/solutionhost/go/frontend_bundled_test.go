package solutionhost_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/stretchr/testify/require"
)

// A page the host bundles is declared by the package and export the host
// mounts, instead of a remote's exposed module and host contract: one
// declaration, one mounting, and no payload, since the host builds what it
// serves. Before this, a module whose page the host bundled declared no
// frontend at all, so nothing downstream of the manifest knew it had a page.
func TestAPageTheHostBundlesIsDeclaredByItsPackageAndExport(t *testing.T) {
	frontend, err := solutionhost.ParseFrontend([]byte("title: Installed models\norder: 60\nbundled: {package: \"@acme/models-ui\", export: modelsPlugin}\n"))
	require.NoError(t, err)
	require.Equal(t, &solutionhost.FrontendBundled{Package: "@acme/models-ui", Export: "modelsPlugin"}, frontend.Bundled)
	require.Empty(t, frontend.ExposedModule)
	require.Zero(t, frontend.HostContract)

	for name, document := range map[string]string{
		"beside exposed_module": "title: Models\norder: 0\nexposed_module: ./Page\nbundled: {package: \"@acme/models-ui\", export: modelsPlugin}\n",
		"beside host_contract":  "title: Models\norder: 0\nhost_contract: 1\nbundled: {package: \"@acme/models-ui\", export: modelsPlugin}\n",
		"with a payload":        "title: Models\norder: 0\nbundled: {package: \"@acme/models-ui\", export: modelsPlugin}\npayload: {artifact: a, digest: d, media_type: m}\n",
		"package omitted":       "title: Models\norder: 0\nbundled: {export: modelsPlugin}\n",
		"export omitted":        "title: Models\norder: 0\nbundled: {package: \"@acme/models-ui\"}\n",
		"export empty":          "title: Models\norder: 0\nbundled: {package: \"@acme/models-ui\", export: \"\"}\n",
		"bundled empty":         "title: Models\norder: 0\nbundled: {}\n",
		"bundled not a mapping": "title: Models\norder: 0\nbundled: [\"@acme/models-ui\"]\n",
		"order omitted":         "title: Models\nbundled: {package: \"@acme/models-ui\", export: modelsPlugin}\n",
	} {
		_, err := solutionhost.ParseFrontend([]byte(document))
		require.ErrorIs(t, err, solutionhost.ErrInvalid, name)
	}
}

// A manifest carrying a bundled page validates, signs canonically, and is
// a page to everything that reads the manifest's frontend; one carrying a
// remote is unchanged, byte for byte, since the field is absent for it.
func TestAManifestCarriesABundledPage(t *testing.T) {
	bundled := strings.Replace(validYAML,
		"  exposed_module: ./Page\n  host_contract: 1\n  payload:\n    artifact: wiki-frontend\n    digest: sha256:0000000000000000000000000000000000000000000000000000000000000001\n    media_type: application/gzip\n",
		"  bundled: {package: \"@acme/wiki-ui\", export: wikiPlugin}\n", 1)
	require.NotEqual(t, validYAML, bundled)
	manifest, err := solutionhost.Parse([]byte(bundled))
	require.NoError(t, err)
	require.NotNil(t, manifest.Frontend)
	require.Equal(t, "@acme/wiki-ui", manifest.Frontend.Bundled.Package)
	require.NoError(t, manifest.Validate())
	canonical, err := manifest.CanonicalBytes()
	require.NoError(t, err)
	require.Contains(t, string(canonical), `"bundled":{"export":"wikiPlugin","package":"@acme/wiki-ui"}`)
	require.NotContains(t, string(canonical), "exposed_module")

	remote, err := valid(t).CanonicalBytes()
	require.NoError(t, err)
	require.NotContains(t, string(remote), "bundled")

	// Mounted two ways in a manifest is refused as it is in the file.
	both := strings.Replace(validYAML, "  host_contract: 1\n", "  host_contract: 1\n  bundled: {package: \"@acme/wiki-ui\", export: wikiPlugin}\n", 1)
	_, err = solutionhost.Parse([]byte(both))
	require.ErrorIs(t, err, solutionhost.ErrInvalid)
	require.Contains(t, err.Error(), "mounted one way")
}
