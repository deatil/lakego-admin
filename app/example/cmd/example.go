package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
)

/**
 * 例子脚本
 *
 * > ./main app:example
 * > main.exe app:example
 * > go run main.go app:example
 *
 * @create 2021-10-11
 * @author deatil
 */
var ExampleCmd = &cobra.Command{
    Use: "app:example",
    Short: "例子信息",
    Example: "{execfile} app:example",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("例子信息显示成功")
    },
}


