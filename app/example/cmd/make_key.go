package cmd

import (
    "fmt"

    "github.com/spf13/cobra"

    "app/example/key"
)

/**
 * 生成各种证书
 *
 * > ./main app:make-key
 * > main.exe app:make-key
 * > go run main.go app:make-key
 *
 * @create 2022-8-27
 * @author deatil
 */
var MakeKeyCmd = &cobra.Command{
    Use: "app:make-key",
    Short: "生成各种证书",
    Example: "{execfile} app:make-key",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        key.NewRsa().Make()

        fmt.Println("生成各种证书成功")
    },
}


