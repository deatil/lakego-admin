package cmd

import (
    "io/ioutil"
    "os/exec"
    "runtime"
    "strings"

    "github.com/deatil/lakego-doak/lakego/command"
    pathTool "github.com/deatil/lakego-doak/lakego/support/path"
)

var stopCmd = &command.Command{
    Use:   "lakego-admin:stop",
    Short: "停止 admin 系统服务",
    Run: func(cmd *command.Command, args []string) {
        file := pathTool.RuntimePath("/pid/lakego.sock")

        pids, err := ioutil.ReadFile(file)
        if err != nil {
            return
        }

        pids := strings.Split(string(pids), ",")

        var command *exec.Cmd

        for _, pid := range pids {
            if runtime.GOOS == "windows" {
                command = exec.Command("taskkill.exe", "/f", "/pid", pid)
            } else {
                command = exec.Command("kill", pid)
            }

            command.Start()
        }
    },
}
