package command

import (
    "io"
    "bytes"
    "context"
    "text/template"

    "github.com/spf13/pflag"
    "github.com/spf13/cobra"
)

type (
    // 脚本
    Command = cobra.Command

    // PositionalArgs
    PositionalArgs = cobra.PositionalArgs

    // FParseErrWhitelist
    FParseErrWhitelist = cobra.FParseErrWhitelist

    // CompletionOptions
    CompletionOptions = cobra.CompletionOptions

    // ShellCompDirective is a bit map representing the different behaviors the shell
    // can be instructed to have once completions have been provided.
    ShellCompDirective = cobra.ShellCompDirective
)

// NoArgs returns an error if any args are included.
func NoArgs(cmd *Command, args []string) error {
    return cobra.NoArgs(cmd, args)
}

// OnlyValidArgs returns an error if any args are not in the list of ValidArgs.
func OnlyValidArgs(cmd *Command, args []string) error {
    return cobra.OnlyValidArgs(cmd, args)
}

// ArbitraryArgs never returns an error.
func ArbitraryArgs(cmd *Command, args []string) error {
    return cobra.ArbitraryArgs(cmd, args)
}

// MinimumNArgs returns an error if there is not at least N args.
func MinimumNArgs(n int) PositionalArgs {
    return cobra.MinimumNArgs(n)
}

// MaximumNArgs returns an error if there are more than N args.
func MaximumNArgs(n int) PositionalArgs {
    return cobra.MaximumNArgs(n)
}

// ExactArgs returns an error if there are not exactly n args.
func ExactArgs(n int) PositionalArgs {
    return cobra.ExactArgs(n)
}

// ExactValidArgs returns an error if
// there are not exactly N positional args OR
// there are any positional args that are not in the `ValidArgs` field of `Command`
func ExactValidArgs(n int) PositionalArgs {
    return cobra.ExactValidArgs(n)
}

// RangeArgs returns an error if the number of args is not within the expected range.
func RangeArgs(min int, max int) PositionalArgs {
    return cobra.RangeArgs(min, max)
}

// AddTemplateFunc adds a template function that's available to Usage and Help
// template generation.
func AddTemplateFunc(name string, tmplFunc any) {
    cobra.AddTemplateFunc(name, tmplFunc)
}

// AddTemplateFuncs adds multiple template functions that are available to Usage and
// Help template generation.
func AddTemplateFuncs(tmplFuncs template.FuncMap) {
    cobra.AddTemplateFuncs(tmplFuncs)
}

// OnInitialize sets the passed functions to be run when each command's
// Execute method is called.
func OnInitialize(y ...func()) {
    cobra.OnInitialize(y...)
}

// Gt takes two types and checks whether the first type is greater than the second. In case of types Arrays, Chans,
// Maps and Slices, Gt will compare their lengths. Ints are compared directly while strings are first parsed as
// ints and then compared.
func Gt(a any, b any) bool {
    return cobra.Gt(a, b)
}

// Eq takes two types and checks whether they are equal. Supported types are int and string. Unsupported types will panic.
func Eq(a any, b any) bool {
    return cobra.Eq(a, b)
}

// CheckErr prints the msg with the prefix 'Error:' and exits with error code 1. If the msg is nil, it does nothing.
func CheckErr(msg any) {
    cobra.CheckErr(msg)
}

// WriteStringAndCheck writes a string into a buffer, and checks if the error is not nil.
func WriteStringAndCheck(b io.StringWriter, s string) {
    cobra.WriteStringAndCheck(b, s)
}

// NoFileCompletions can be used to disable file completion for commands that should
// not trigger file completions.
func NoFileCompletions(cmd *Command, args []string, toComplete string) ([]string, ShellCompDirective) {
    return cobra.NoFileCompletions(cmd, args, toComplete)
}

// CompDebug prints the specified string to the same file as where the
// completion script prints its logs.
// Note that completion printouts should never be on stdout as they would
// be wrongly interpreted as actual completion choices by the completion script.
func CompDebug(msg string, printToStdErr bool) {
    cobra.CompDebug(msg, printToStdErr)
}

// CompDebugln prints the specified string with a newline at the end
// to the same file as where the completion script prints its logs.
// Such logs are only printed when the user has set the environment
// variable BASH_COMP_DEBUG_FILE to the path of some file to be used.
func CompDebugln(msg string, printToStdErr bool) {
    cobra.CompDebugln(msg, printToStdErr)
}

// CompError prints the specified completion message to stderr.
func CompError(msg string) {
    cobra.CompError(msg)
}

// CompErrorln prints the specified completion message to stderr with a newline at the end.
func CompErrorln(msg string) {
    cobra.CompErrorln(msg)
}

// MarkFlagRequired instructs the various shell completion implementations to
// prioritize the named flag when performing completion,
// and causes your command to report an error if invoked without the flag.
func MarkFlagRequired(flags *pflag.FlagSet, name string) error {
    return cobra.MarkFlagRequired(flags, name)
}

// MarkFlagFilename instructs the various shell completion implementations to
// limit completions for the named flag to the specified file extensions.
func MarkFlagFilename(flags *pflag.FlagSet, name string, extensions ...string) error {
    return cobra.MarkFlagFilename(flags, name, extensions...)
}

// MarkFlagCustom adds the BashCompCustom annotation to the named flag, if it exists.
// The bash completion script will call the bash function f for the flag.
//
// This will only work for bash completion.
// It is recommended to instead use c.RegisterFlagCompletionFunc(...) which allows
// to register a Go function which will work across all shells.
func MarkFlagCustom(flags *pflag.FlagSet, name string, f string) error {
    return cobra.MarkFlagCustom(flags, name, f)
}

// MarkFlagDirname instructs the various shell completion implementations to
// limit completions for the named flag to directory names.
func MarkFlagDirname(flags *pflag.FlagSet, name string) error {
    return cobra.MarkFlagDirname(flags, name)
}

// 执行脚本
func ExecuteCommand(root *cobra.Command, args ...string) (output string, err error) {
    _, output, err = ExecuteCommandC(root, args...)
    return output, err
}

// ctx := context.TODO()
func ExecuteCommandWithContext(ctx context.Context, root *cobra.Command, args ...string) (output string, err error) {
    buf := new(bytes.Buffer)
    root.SetOut(buf)
    root.SetErr(buf)
    root.SetArgs(args)

    err = root.ExecuteContext(ctx)

    return buf.String(), err
}

func ExecuteCommandC(root *cobra.Command, args ...string) (c *cobra.Command, output string, err error) {
    buf := new(bytes.Buffer)
    root.SetOut(buf)
    root.SetErr(buf)
    root.SetArgs(args)

    c, err = root.ExecuteC()

    return c, buf.String(), err
}

// ctx := context.TODO()
func ExecuteCommandWithContextC(ctx context.Context, root *cobra.Command, args ...string) (c *cobra.Command, output string, err error) {
    buf := new(bytes.Buffer)
    root.SetOut(buf)
    root.SetErr(buf)
    root.SetArgs(args)

    c, err = root.ExecuteContextC(ctx)

    return c, buf.String(), err
}

