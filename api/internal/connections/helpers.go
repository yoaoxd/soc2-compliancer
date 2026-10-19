package connections

import "encoding/json"

func jsonStrings(s []string) string {
	if s == nil {
		s = []string{}
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func jsonMap(m map[string]any) string {
	if m == nil {
		m = map[string]any{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}
