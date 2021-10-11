package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
)

/**
 * 用户信息
 *
 * > ./main app:user-info
 * > main.exe app:user-info
 * > go run main.go app:user-info
 *
 * @create 2021-10-11
 * @author deatil
 */
var UserInfoCmd = &cobra.Command{
    Use: "app:user-info",
    Short: "显示用户信息",
    Example: "{execfile} app:user-info",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("用户信息")
    },
}


