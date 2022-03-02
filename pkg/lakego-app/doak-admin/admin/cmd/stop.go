package cmd

import (
    "strconv"
    "strings"

    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/filesystem"
    cmdTool "github.com/deatil/lakego-doak/lakego/support/cmd"
    pathTool "github.com/deatil/lakego-doak/lakego/support/path"
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
    pidPath := config.New("admin").GetString("PidPath")
    location := pathTool.FormatPath(pidPath)

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

    color.Greenln("系统服务正在停止...")

    if stopPid == "" {
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
