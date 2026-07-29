package listing

import (
	"strings"
	"testing"
)

// A heredoc body is data, not shell. Colouring "gpgcheck=0" as a command tells
// the reader something false about what they are pasting, which is worse than
// leaving it plain.
func TestHeredocBodyIsNotHighlighted(t *testing.T) {
	marked := highlightShellBlock([]string{
		"sudo tee /etc/yum.repos.d/x.repo > /dev/null <<'REPO'",
		"[x]",
		"gpgcheck=0",
		"REPO",
		"sudo dnf install x",
	})
	if !strings.Contains(marked[0], `class="s-command">sudo`) {
		t.Fatal("the command opening the heredoc lost its highlighting")
	}
	for _, line := range marked[1:4] {
		if strings.Contains(line, "s-command") {
			t.Fatalf("heredoc content was highlighted as shell: %q", line)
		}
	}
	if !strings.Contains(marked[4], `class="s-command">sudo`) {
		t.Fatal("highlighting did not resume after the heredoc terminator")
	}
}

// A quoted delimiter is what instructions use so the shell does not expand the
// body; an unquoted one behaves the same way for this purpose.
func TestHeredocDelimiterForms(t *testing.T) {
	for line, want := range map[string]string{
		"cat <<'EOF'":            "EOF",
		"cat <<EOF":              "EOF",
		"cat <<-END > /tmp/x":    "END",
		`cat <<"CONF"`:           "CONF",
		"echo not a heredoc":     "",
		"echo a << b":            "b",
		"sudo tee x <<'UNCLOSED": "",
	} {
		if got := heredocDelimiter(line); got != want {
			t.Fatalf("heredocDelimiter(%q) = %q, want %q", line, got, want)
		}
	}
}

// A line ending in a backslash continues the one before it, so the word that
// starts the next line is an argument rather than a command.
func TestContinuationIsNotANewCommand(t *testing.T) {
	marked := highlightShellBlock([]string{
		"sudo curl -fsSL -o /etc/apk/keys/x.rsa.pub \\",
		"  https://dl.example/alpine/keys/x.rsa.pub",
		"sudo apk add x",
	})
	if strings.Contains(marked[1], "s-command") {
		t.Fatalf("a continuation line was highlighted as a command: %q", marked[1])
	}
	if !strings.Contains(marked[2], `class="s-command">sudo`) {
		t.Fatal("the line after the continuation is a command again")
	}
}
