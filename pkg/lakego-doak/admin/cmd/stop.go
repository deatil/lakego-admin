package cmd

import (
    "io"
    "os"
    "fmt"
    "strconv"
    "strings"

    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    cmdTool "github.com/deatil/lakego-doak/lakego/support/cmd"
    pathTool "github.com/deatil/lakego-doak/lakego/support/path"
)

/**
 * 停止 admin 系统服务
 *
 * > ./main lakego-admin:stop
 * > main.exe lakego-admin:stop
 * > go run main.go lakego-admin:stop
 *
 * @create 2022-2-13
 * @author deatil
 */
var StopCmd = &command.Command{
    Use:   "lakego-admin:stop",
    Short: "停止 admin 系统服务",
    Run: func(cmd *command.Command, args []string) {
        pidPath := config.New("admin").GetString("PidPath")

        location := pathTool.FormatPath(pidPath)

        file, e := os.Open(location)
        if e != nil {
            color.Red(e.Error())

            return
        }
        defer file.Close()

        data, err := io.ReadAll(file)
        if err != nil {
            color.Red(err.Error())

            return
        }

        contents := fmt.Sprintf("%s", string(data))

        pids := strings.Split(contents, ",")

        if len(pids) == 0 {
            color.Red("pid 数据为空")

            return
        }

        color.Green("系统服务正在停止...\n")

        for _, pid := range pids {
            id, err2 := strconv.Atoi(pid)
            if err2 == nil {
                _, err3 := cmdTool.New().Kill(id)
                if err3 != nil {
                    fmt.Println(err3.Error())
                }
            }
        }

    },
}
