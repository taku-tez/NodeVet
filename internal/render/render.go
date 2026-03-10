package render

import (
	"io"

	"github.com/NodeVet/nodevet/internal/checker"
)

// Renderer renders a checker.Result to an output stream.
type Renderer interface {
	Render(result *checker.Result) error
}

// New returns the default table renderer.
func New(w io.Writer) Renderer {
	return &TableRenderer{w: w}
}
