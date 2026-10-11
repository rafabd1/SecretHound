package finding

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type Finding struct {
	Type             string  `json:"type"`
	Value            string  `json:"value"`
	URL              string  `json:"url"`
	Line             int     `json:"line,omitempty"`
	Context          string  `json:"context,omitempty"`
	Confidence       float64 `json:"confidence,omitempty"`
	Description      string  `json:"description,omitempty"`
	FilterStatus     string  `json:"filter_status,omitempty"`
	FilterScore      float64 `json:"filter_score,omitempty"`
	ReviewPriority   string  `json:"review_priority,omitempty"`
	ByteOffset       int     `json:"byte_offset"`
	ContextOffset    int     `json:"-"`
	HasContextOffset bool    `json:"-"`
}

func New(secretType, value, context, url string, line int) Finding {
	return Finding{
		Type:       secretType,
		Value:      value,
		Context:    context,
		URL:        url,
		Line:       line,
		Confidence: 0.8,
	}
}

func ExtractContext(content, match string, contextSize int) string {
	idx := strings.Index(content, match)
	if idx == -1 {
		return ""
	}
	return ExtractContextAt(content, idx, idx+len(match), contextSize)
}

func ExtractContextAt(content string, start, end, contextSize int) string {
	context, _ := ExtractContextAtWithMatchOffset(content, start, end, contextSize)
	return context
}

func ExtractContextAtWithMatchOffset(content string, start, end, contextSize int) (string, int) {
	if start < 0 || end < start || end > len(content) {
		return "", -1
	}
	contextStart := max(0, start-contextSize)
	contextEnd := min(len(content), end+contextSize)
	for contextStart > 0 && contextStart < len(content) && !utf8.RuneStart(content[contextStart]) {
		contextStart--
	}
	for contextEnd < len(content) && !utf8.RuneStart(content[contextEnd]) {
		contextEnd++
	}
	return content[contextStart:contextEnd], start - contextStart
}

func (f Finding) GetSafeValue(maskLength int) string {
	if len(f.Value) <= maskLength {
		return strings.Repeat("*", len(f.Value))
	}

	visible := min(3, len(f.Value)/4)
	return f.Value[:visible] + strings.Repeat("*", len(f.Value)-visible*2) + f.Value[len(f.Value)-visible:]
}

func (f Finding) String() string {
	url := f.URL
	if f.Line > 0 {
		url = fmt.Sprintf("%s#L%d", url, f.Line)
	}

	return fmt.Sprintf("[%s] %s in %s", f.Type, f.GetSafeValue(4), url)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
