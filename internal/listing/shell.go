package listing

import (
	"bytes"
	"strings"
)

// highlightShellBlock marks up a run of shell lines.
//
// It exists because two very common shapes in install instructions are not
// visible one line at a time. A line ending in a backslash continues the one
// before it, so its first word is an argument rather than a command; and
// everything between a heredoc marker and its terminator is data, not shell at
// all. Highlighting those as commands is worse than not highlighting them —
// it tells the reader something false about what they are about to paste.
func highlightShellBlock(lines []string) []string {
	marked := make([]string, 0, len(lines))
	heredoc := ""
	continued := false
	for _, line := range lines {
		if heredoc != "" {
			marked = append(marked, escape(line))
			if strings.TrimSpace(line) == heredoc {
				heredoc = ""
			}
			continue
		}
		marked = append(marked, highlightShellLine(line, continued))
		heredoc = heredocDelimiter(line)
		continued = strings.HasSuffix(strings.TrimRight(line, " \t"), "\\")
	}
	return marked
}

// heredocDelimiter reports the word that ends a heredoc opened on this line,
// or empty where none is. Only the unquoted and single-quoted forms are
// recognised, which is what instructions use to write a config file.
func heredocDelimiter(line string) string {
	marker := strings.Index(line, "<<")
	if marker < 0 {
		return ""
	}
	rest := strings.TrimPrefix(line[marker+2:], "-")
	rest = strings.TrimLeft(rest, " \t")
	quote := byte(0)
	if len(rest) > 0 && (rest[0] == '\'' || rest[0] == '"') {
		quote = rest[0]
		rest = rest[1:]
	}
	end := 0
	for end < len(rest) && (rest[end] == '_' || rest[end] == '-' ||
		(rest[end] >= 'A' && rest[end] <= 'Z') || (rest[end] >= 'a' && rest[end] <= 'z') ||
		(rest[end] >= '0' && rest[end] <= '9')) {
		end++
	}
	word := rest[:end]
	if word == "" {
		return ""
	}
	if quote != 0 && (end >= len(rest) || rest[end] != quote) {
		return ""
	}
	return word
}

// highlightShell marks up a line of shell for reading.
//
// The markup is produced here rather than by a highlighter the page loads,
// because the page has to be self-contained: a repository is a content-addressed
// tree, and a script fetched from somewhere else is a dependency a published
// index should not have. The colouring is deliberately shallow — comments,
// quoted strings, the command word, and flags — which is what makes a paste
// target readable without pretending to parse shell.
func highlightShell(line string) string { return highlightShellLine(line, false) }

// highlightShellLine marks up one line. continued says the previous line ended
// in a backslash, in which case nothing here starts a command.
func highlightShellLine(line string, continued bool) string {
	trimmed := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmed)]
	if strings.HasPrefix(trimmed, "#") {
		return indent + span("comment", trimmed)
	}

	var out bytes.Buffer
	out.WriteString(indent)
	rest := trimmed
	firstWord := !continued
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
