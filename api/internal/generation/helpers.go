package generation

import (
	"encoding/json"
	"os"
	"regexp"
)

var outputRE = regexp.MustCompile(`(?m)^output\s+"([^"]+)"`)

func jsonStrings(s []string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// extractOutputs returns the output names declared in a module's outputs.tf
// by parsing `output "name"` lines (we own the library, so this is safe).
func extractOutputs(dir string) []string {
	b, err := os.ReadFile(dir + "/outputs.tf")
	if err != nil {
		return nil
	}
	matches := outputRE.FindAllStringSubmatch(string(b), -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}
