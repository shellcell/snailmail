package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
func (flags *commandFlags) Parse(arguments []string) error { return flags.set.Parse(arguments) }
func (flags *commandFlags) NArg() int                      { return flags.set.NArg() }
func (flags *commandFlags) Arg(index int) string           { return flags.set.Arg(index) }
func (flags *commandFlags) Args() []string                 { return flags.set.Args() }

// parse reads arguments and rejects any positional argument, which every
// command using it treats as a usage error.
func (flags *commandFlags) parse(arguments []string) error {
	if err := flags.set.Parse(arguments); err != nil {
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
	if err := flags.set.Parse(arguments); err != nil {
		return nil, err
	}
	if flags.set.NArg() != count {
		return nil, errors.New(usage)
	}
	return flags.set.Args(), nil
}
