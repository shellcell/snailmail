package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// commandFlags removes the boilerplate every subcommand repeated: routing usage
// output to stderr, declaring the shared --workspace flag, and rejecting
// positional arguments the command does not take.
type commandFlags struct {
	set       *flag.FlagSet
	workspace *string
	json      *bool
}

func newCommandFlags(name string, stderr io.Writer) *commandFlags {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	return &commandFlags{set: set}
}

// withWorkspace declares the shared workspace root flag, under both names it is
// reasonably called.
//
// --workspace is the documented one. --root is accepted because it is what the
// engine calls the same thing everywhere — workspaceRoot, Request.Root,
// flags.Root — so anyone who has read the source guesses it, as does anyone
// thinking of a workspace as a directory. A flag error is a poor thing to spend a
// reader's attention on when the intent was unambiguous.
//
// Both write to one variable, so either may be given and the last wins.
func (flags *commandFlags) withWorkspace() *commandFlags {
	root := "."
	flags.workspace = &root
	flags.set.Var(&stringFlag{target: &root}, "workspace", "workspace root")
	flags.set.Var(&stringFlag{target: &root}, "root", "workspace root (alias for --workspace)")
	return flags
}

// stringFlag lets two flag names share one destination. The flag package prints
// usage by calling String on a zero value, so it has to tolerate no target.
type stringFlag struct{ target *string }

func (value *stringFlag) String() string {
	if value == nil || value.target == nil {
		return ""
	}
	return *value.target
}

func (value *stringFlag) Set(given string) error {
	*value.target = given
	return nil
}

func (flags *commandFlags) String(name, value, usage string) *string {
	return flags.set.String(name, value, usage)
}

func (flags *commandFlags) Bool(name string, value bool, usage string) *bool {
	return flags.set.Bool(name, value, usage)
}

func (flags *commandFlags) Int(name string, value int, usage string) *int {
	return flags.set.Int(name, value, usage)
}

func (flags *commandFlags) Int64(name string, value int64, usage string) *int64 {
	return flags.set.Int64(name, value, usage)
}

func (flags *commandFlags) Duration(name string, value time.Duration, usage string) *time.Duration {
	return flags.set.Duration(name, value, usage)
}

// withJSON declares the shared machine-readable output flag. PLAN.md §13:
// "--json on everything, so CI is the CLI in a container."
func (flags *commandFlags) withJSON() *commandFlags {
	flags.json = flags.set.Bool("json", false, "emit machine-readable JSON")
	return flags
}

// emit writes the command's result as JSON when it was asked for, and reports
// whether it did so the caller renders either machine-readable or human output
// and never both. Both renderings read the same typed value, so they cannot
// drift apart.
func (flags *commandFlags) emit(stdout io.Writer, result any) (bool, error) {
	if flags.json == nil || !*flags.json {
		return false, nil
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return true, encoder.Encode(result)
}

// jsonRequested reports whether machine-readable output was asked for, so a
// command can suppress a narration that would sit around the one document a
// caller wants.
func (flags *commandFlags) jsonRequested() bool {
	return flags.json != nil && *flags.json
}

// Root is the resolved workspace root, or "." for commands without the flag.
func (flags *commandFlags) Root() string {
	if flags.workspace == nil {
		return "."
	}
	return *flags.workspace
}

// Parse, NArg, Arg and Args pass through for the commands that take positional
// arguments and validate the count themselves.
func (flags *commandFlags) Parse(arguments []string) error {
	return flags.set.Parse(hoistFlags(flags.set, arguments))
}
func (flags *commandFlags) NArg() int            { return flags.set.NArg() }
func (flags *commandFlags) Arg(index int) string { return flags.set.Arg(index) }
func (flags *commandFlags) Args() []string       { return flags.set.Args() }

// parse reads arguments and rejects any positional argument, which every
// command using it treats as a usage error.
func (flags *commandFlags) parse(arguments []string) error {
	if err := flags.set.Parse(hoistFlags(flags.set, arguments)); err != nil {
		return err
	}
	if flags.set.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.set.Arg(0))
	}
	return nil
}

// parseWithArguments reads arguments and requires exactly count positional
// arguments, reporting usage when the count does not match.
func (flags *commandFlags) parseWithArguments(arguments []string, count int, usage string) ([]string, error) {
	if err := flags.set.Parse(hoistFlags(flags.set, arguments)); err != nil {
		return nil, err
	}
	if flags.set.NArg() != count {
		return nil, errors.New(usage)
	}
	return flags.set.Args(), nil
}

// hoistFlags reorders arguments so flags may appear anywhere, including after
// positional ones.
//
// Go's flag package stops parsing at the first argument that is not a flag, so
// `snailmail doctor URL --json` silently treats --json as a positional and reports
// a usage error that does not mention it. Every CLI people arrive from — git,
// docker, kubectl, gh, cargo — accepts flags in any position, so the strict
// behaviour reads as a bug rather than a convention. It cost three separate
// mistakes while building features in this repository, which is a fair prediction
// of how a newcomer fares.
//
// Everything after a bare "--" is left alone, which is what lets an artifact
// legitimately be named "-weird.deb".
func hoistFlags(set *flag.FlagSet, arguments []string) []string {
	var flags, positional []string
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			// Everything after the caller's terminator is positional, whatever it
			// looks like. The terminator itself is dropped here and reinstated below,
			// so it always lands between the flags and the positionals rather than
			// wherever the caller happened to put it.
			positional = append(positional, arguments[index+1:]...)
			break
		}
		if len(argument) < 2 || argument[0] != '-' {
			positional = append(positional, argument)
			continue
		}
		flags = append(flags, argument)
		if strings.Contains(argument, "=") {
			continue
		}
		// A non-boolean flag takes the next argument as its value, so that argument
		// has to travel with it rather than being read as a positional. An unknown
		// flag is left to Parse, which reports it better than this could.
		declared := set.Lookup(strings.TrimLeft(argument, "-"))
		if declared == nil {
			continue
		}
		if boolean, ok := declared.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if index+1 < len(arguments) {
			index++
			flags = append(flags, arguments[index])
		}
	}
	if len(positional) == 0 {
		return flags
	}
	// A terminator of our own, always. Without it an artifact legitimately named
	// "-weird.deb" is read as a flag, and a positional that arrived before a flag
	// would stop parsing early and undo the hoist.
	return append(append(flags, "--"), positional...)
}

// wasSet reports whether a flag was given on the command line, as opposed to
// holding its default.
//
// Needed where every value of a flag means something and "unspecified" is a
// distinct third answer — collect's --keep, where zero is a real retention and a
// negative one is an error the operator must still be told about, so neither can
// double as a sentinel.
func (flags *commandFlags) wasSet(name string) bool {
	given := false
	flags.set.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}
