package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
)

var InstallCmd = &cobra.Command{
    Use: "install",
    Short: "Install the lakego-admin.",
    Example: "{execfile} install",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("install successfully.")
    },
}
