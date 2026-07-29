package listing

import (
	"bytes"
	"strings"
)

// highlightShell marks up a line of shell for reading.
//
// The markup is produced here rather than by a highlighter the page loads,
// because the page has to be self-contained: a repository is a content-addressed
// tree, and a script fetched from somewhere else is a dependency a published
// index should not have. The colouring is deliberately shallow — comments,
// quoted strings, the command word, and flags — which is what makes a paste
// target readable without pretending to parse shell.
func highlightShell(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmed)]
	if strings.HasPrefix(trimmed, "#") {
		return indent + span("comment", trimmed)
	}

	var out bytes.Buffer
	out.WriteString(indent)
	rest := trimmed
	firstWord := true
	for len(rest) > 0 {
		switch {
		case rest[0] == '\'' || rest[0] == '"':
			quote := rest[0]
			end := strings.IndexByte(rest[1:], quote)
			if end < 0 {
				// An unterminated quote runs to the end of the line, which is
				// what a heredoc body looks like when it is split across lines.
				out.WriteString(span("string", rest))
				return out.String()
			}
			out.WriteString(span("string", rest[:end+2]))
			rest = rest[end+2:]
			firstWord = false
		case rest[0] == ' ' || rest[0] == '\t':
			end := 1
			for end < len(rest) && (rest[end] == ' ' || rest[end] == '\t') {
				end++
			}
			out.WriteString(rest[:end])
			rest = rest[end:]
		default:
			end := strings.IndexAny(rest, " \t'\"")
			if end < 0 {
				end = len(rest)
			}
			word := rest[:end]
			switch {
			case strings.HasPrefix(word, "-"):
				out.WriteString(span("flag", word))
			case firstWord && word != "|" && word != "\\":
				out.WriteString(span("command", word))
			default:
				out.WriteString(escape(word))
			}
			// A pipe starts a new command, so the next word is one again.
			firstWord = word == "|" || word == "&&" || word == "||" || word == ";"
			rest = rest[end:]
		}
	}
	return out.String()
}

func span(class, text string) string {
	return `<span class="s-` + class + `">` + escape(text) + `</span>`
}
