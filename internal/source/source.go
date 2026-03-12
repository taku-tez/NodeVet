package source

// ConfigSource produces a flat key→value map of kubelet configuration.
// Keys are canonical flag names without leading dashes (e.g. "anonymous-auth").
type ConfigSource interface {
	Load() (map[string]string, error)
	SourceName() string
}

// Merge merges multiple source maps. Later sources override earlier ones.
func Merge(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// Discrepancy describes a key where the static (desired) config and the live
// (running) config disagree. This may indicate a misconfiguration drift or a
// config reload failure.
type Discrepancy struct {
	Key         string
	StaticValue string // value from YAML / flag sources
	LiveValue   string // value from configz (running kubelet)
}

// FindDiscrepancies compares static (desired) and live (running) config maps.
// Returns entries where both maps have a value for the same key but the values differ.
func FindDiscrepancies(static, live map[string]string) []Discrepancy {
	var result []Discrepancy
	for key, liveVal := range live {
		staticVal, ok := static[key]
		if !ok {
			continue // key only in live — not a discrepancy, just extra info
		}
		if staticVal != liveVal {
			result = append(result, Discrepancy{
				Key:         key,
				StaticValue: staticVal,
				LiveValue:   liveVal,
			})
		}
	}
	return result
}
