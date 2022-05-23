package cmd

import (
    "strconv"
    "strings"

    cmdTool "github.com/deatil/go-cmd/cmd"
    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

/**
 * 停止 admin 系统服务
 *
 * > ./main lakego-admin:stop [--pid=12345]
 * > main.exe lakego-admin:stop [--pid=12345]
 * > go run main.go lakego-admin:stop [--pid=12345]
 *
 * @create 2022-2-13
 * @author deatil
 */
var StopCmd = &command.Command{
    Use:   "lakego-admin:stop",
    Short: "停止 admin 系统服务",
    Run: func(cmd *command.Command, args []string) {
        Stop()
    },
}

// 自定义 Pid
var stopPid string

func init() {
    pf := StopCmd.Flags()
    pf.StringVarP(&stopPid, "pid", "p", "", "要停止的pid")
}

// 停止 admin 系统服务
func Stop() {
    color.Greenln("系统服务正在停止...")

    if stopPid == "" {
        pidPath := config.New("admin").GetString("pid-path")
        location := path.FormatPath(pidPath)

        contents, err := filesystem.New().Get(location)
        if err != nil {
            color.Redln(err.Error())

            return
        }

        pids := strings.Split(contents, ",")
        if len(pids) == 0 {
            color.Redln("pid 数据为空")

            return
        }

        for _, pid := range pids {
            id, err2 := strconv.Atoi(pid)
            if err2 == nil {
                _, err3 := cmdTool.New().Kill(id)
                if err3 != nil {
                    color.Redln(err3.Error())
                }
            }
        }
    } else {
        id, err2 := strconv.Atoi(stopPid)
        if err2 == nil {
            _, err3 := cmdTool.New().Kill(id)
            if err3 != nil {
                color.Redln(err3.Error())
            }
        }
    }
}
