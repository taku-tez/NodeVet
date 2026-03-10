package source

import "strings"

// FlagSource parses a raw kubelet flags string like:
// "--anonymous-auth=false --tls-cert-file=/etc/k8s/kubelet.crt"
type FlagSource struct {
	flags string
}

// NewFlagSource creates a FlagSource from a raw flags string.
func NewFlagSource(flags string) *FlagSource {
	return &FlagSource{flags: flags}
}

func (s *FlagSource) SourceName() string { return "flags" }

func (s *FlagSource) Load() (map[string]string, error) {
	result := make(map[string]string)
	tokens := splitFlags(s.flags)
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		// Strip leading -- or -
		key := strings.TrimLeft(token, "-")
		val := "true"
		if idx := strings.Index(key, "="); idx != -1 {
			val = key[idx+1:]
			key = key[:idx]
		}
		result[key] = val
	}
	return result, nil
}

// splitFlags splits a flags string on whitespace but respects quoted values.
func splitFlags(s string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQuote = true
			quoteChar = c
		case c == ' ' || c == '\t' || c == '\n':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}
