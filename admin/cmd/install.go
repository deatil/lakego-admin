package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
)

/**
 * 安装脚本
 *
 * > ./main lakego-admin:install
 * > main.exe lakego-admin:install
 * > go run main.go lakego-admin:install
 *
 * @create 2021-8-15
 * @author deatil
 */
var InstallCmd = &cobra.Command{
    Use: "lakego-admin:install",
    Short: "Install the lakego-admin.",
    Example: "{execfile} install",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("install successfully.")
    },
}
