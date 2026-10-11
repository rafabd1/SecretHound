package finding

import (
	"testing"
	"unicode/utf8"
)

func TestExtractContextAtPreservesUTF8Boundaries(t *testing.T) {
	content := "áMarinaé"
	context := ExtractContextAt(content, len("á"), len("áMarina"), 1)

	if !utf8.ValidString(context) {
		t.Fatalf("context contains invalid UTF-8: %q", context)
	}
	if context != content {
		t.Fatalf("context = %q, want %q", context, content)
	}
}
