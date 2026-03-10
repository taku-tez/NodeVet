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
