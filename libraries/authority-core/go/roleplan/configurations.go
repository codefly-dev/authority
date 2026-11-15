package roleplan

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	modulecontract "github.com/codefly-dev/core/contracts/module"
)

// Configurations are the values a composition supplies, read from one
// directory of Codefly workspace configurations (configurations/<environment>
// in a playground): each <group>.env file a group, each KEY=VALUE line one
// record, every record kept as supplied, since selecting among them is core's
// resolution, never a provider's (modulecontract.Values).
func Configurations(dir string) modulecontract.Values { return configurations(dir) }

type configurations string

// Records implements modulecontract.Values. A group with no file has none.
func (dir configurations) Records(group string) ([]modulecontract.Record, error) {
	data, err := os.ReadFile(filepath.Join(string(dir), group+".env"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []modulecontract.Record
	lines := bufio.NewScanner(bytes.NewReader(data))
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		if key, value, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			out = append(out, modulecontract.Record{Key: strings.TrimSpace(key), Value: strings.TrimSpace(value)})
		}
	}
	return out, lines.Err()
}
