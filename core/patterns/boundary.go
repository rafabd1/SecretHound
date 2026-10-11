package patterns

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
)

const maxTokenAlphabetSize = 96

type asciiRuneSet [128]bool

// compilePatternRegex prevents a bounded capture from ending early when its
// following delimiter also accepts a character from the capture's alphabet.
// The rewrite is deliberately narrow: it only changes the delimiter that
// immediately follows capture group 1, which is the value returned by the
// detector, and only when that capture has a bounded ASCII token alphabet.
func compilePatternRegex(expression string) (*regexp.Regexp, error) {
	// Imported provider patterns use a short bridge between the provider name
	// and the captured value. Let that bridge cross formatting whitespace; the
	// validation layer still requires a credential label tied to the same match.
	expression = strings.Replace(expression, ".{0,40}", `(?s:.{0,40})`, 1)

	parsed, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return nil, err
	}

	if !hardenCapturedValueDelimiter(parsed, 1) {
		return regexp.Compile(expression)
	}

	return regexp.Compile(parsed.String())
}

func hardenCapturedValueDelimiter(expression *syntax.Regexp, captureNumber int) bool {
	changed := false
	if expression.Op == syntax.OpConcat {
		for index, part := range expression.Sub {
			if part.Op != syntax.OpCapture || part.Cap != captureNumber || len(part.Sub) != 1 {
				continue
			}

			alphabet, _, ok := terminalASCIIAlphabet(part.Sub[0])
			if !ok || alphabet.count() == 0 || alphabet.count() > maxTokenAlphabetSize {
				continue
			}

			for next := index + 1; next < len(expression.Sub); next++ {
				if isZeroWidth(expression.Sub[next]) {
					continue
				}
				if hardenDelimiter(expression.Sub[next], alphabet) {
					changed = true
				}
				break
			}
		}
	}

	for _, child := range expression.Sub {
		if hardenCapturedValueDelimiter(child, captureNumber) {
			changed = true
		}
	}
	return changed
}

func hardenDelimiter(expression *syntax.Regexp, alphabet asciiRuneSet) bool {
	switch expression.Op {
	case syntax.OpCharClass:
		return subtractAlphabetFromClass(expression, alphabet)
	case syntax.OpAlternate:
		changed := false
		for _, branch := range expression.Sub {
			if branch.Op == syntax.OpCharClass && subtractAlphabetFromClass(branch, alphabet) {
				changed = true
			}
		}
		return changed
	case syntax.OpCapture:
		if len(expression.Sub) == 1 {
			return hardenDelimiter(expression.Sub[0], alphabet)
		}
	}
	return false
}

func subtractAlphabetFromClass(class *syntax.Regexp, alphabet asciiRuneSet) bool {
	if class.Op != syntax.OpCharClass || len(class.Rune)%2 != 0 {
		return false
	}

	targets := alphabet.runes()
	updated := make([]rune, 0, len(class.Rune)+len(targets)*2)
	changed := false
	for index := 0; index < len(class.Rune); index += 2 {
		low, high := class.Rune[index], class.Rune[index+1]
		cursor := low
		for _, target := range targets {
			if target < cursor || target > high {
				continue
			}
			if cursor < target {
				updated = append(updated, cursor, target-1)
			}
			cursor = target + 1
			changed = true
		}
		if cursor <= high {
			updated = append(updated, cursor, high)
		}
	}

	// An empty mandatory delimiter cannot be represented without changing the
	// surrounding expression. Leave that uncommon shape untouched.
	if !changed || len(updated) == 0 {
		return false
	}
	class.Rune = updated
	return true
}

func terminalASCIIAlphabet(expression *syntax.Regexp) (asciiRuneSet, bool, bool) {
	var alphabet asciiRuneSet
	if expression == nil {
		return alphabet, false, false
	}

	switch expression.Op {
	case syntax.OpNoMatch:
		return alphabet, false, true
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return alphabet, true, true
	case syntax.OpLiteral:
		if len(expression.Rune) == 0 {
			return alphabet, true, true
		}
		addASCIIFolds(&alphabet, expression.Rune[len(expression.Rune)-1], expression.Flags&syntax.FoldCase != 0)
		return alphabet, false, true
	case syntax.OpCharClass:
		for index := 0; index+1 < len(expression.Rune); index += 2 {
			low := maxRune(expression.Rune[index], 0)
			high := minRune(expression.Rune[index+1], 127)
			for character := low; character <= high; character++ {
				alphabet[character] = true
			}
		}
		return alphabet, false, alphabet.count() <= maxTokenAlphabetSize
	case syntax.OpCapture:
		if len(expression.Sub) != 1 {
			return alphabet, false, false
		}
		return terminalASCIIAlphabet(expression.Sub[0])
	case syntax.OpConcat:
		nullable := true
		for index := len(expression.Sub) - 1; index >= 0; index-- {
			childAlphabet, childNullable, ok := terminalASCIIAlphabet(expression.Sub[index])
			if !ok {
				return alphabet, false, false
			}
			alphabet.merge(childAlphabet)
			if alphabet.count() > maxTokenAlphabetSize {
				return alphabet, false, false
			}
			if !childNullable {
				nullable = false
				break
			}
		}
		return alphabet, nullable, true
	case syntax.OpAlternate:
		nullable := false
		for _, branch := range expression.Sub {
			branchAlphabet, branchNullable, ok := terminalASCIIAlphabet(branch)
			if !ok {
				return alphabet, false, false
			}
			alphabet.merge(branchAlphabet)
			if alphabet.count() > maxTokenAlphabetSize {
				return alphabet, false, false
			}
			nullable = nullable || branchNullable
		}
		return alphabet, nullable, true
	case syntax.OpStar, syntax.OpQuest:
		if len(expression.Sub) != 1 {
			return alphabet, false, false
		}
		alphabet, _, ok := terminalASCIIAlphabet(expression.Sub[0])
		return alphabet, true, ok
	case syntax.OpPlus:
		if len(expression.Sub) != 1 {
			return alphabet, false, false
		}
		return terminalASCIIAlphabet(expression.Sub[0])
	case syntax.OpRepeat:
		if len(expression.Sub) != 1 {
			return alphabet, false, false
		}
		if expression.Max == 0 {
			return alphabet, true, true
		}
		alphabet, childNullable, ok := terminalASCIIAlphabet(expression.Sub[0])
		return alphabet, expression.Min == 0 || childNullable, ok
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return alphabet, false, false
	default:
		return alphabet, false, false
	}
}

func addASCIIFolds(alphabet *asciiRuneSet, character rune, folded bool) {
	if character >= 0 && character < 128 {
		alphabet[character] = true
	}
	if !folded {
		return
	}
	for next := unicode.SimpleFold(character); next != character; next = unicode.SimpleFold(next) {
		if next >= 0 && next < 128 {
			alphabet[next] = true
		}
	}
}

func isZeroWidth(expression *syntax.Regexp) bool {
	switch expression.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	default:
		return false
	}
}

func (set *asciiRuneSet) merge(other asciiRuneSet) {
	for index, present := range other {
		if present {
			set[index] = true
		}
	}
}

func (set asciiRuneSet) count() int {
	count := 0
	for _, present := range set {
		if present {
			count++
		}
	}
	return count
}

func (set asciiRuneSet) runes() []rune {
	characters := make([]rune, 0, set.count())
	for index, present := range set {
		if present {
			characters = append(characters, rune(index))
		}
	}
	return characters
}

func minRune(left, right rune) rune {
	if left < right {
		return left
	}
	return right
}

func maxRune(left, right rune) rune {
	if left > right {
		return left
	}
	return right
}
