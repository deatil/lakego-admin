package command

import (
    "os"
    "os/exec"
    "bytes"
    "path/filepath"
)

/**
 * 脚本扩展
 *
 * 使用:
 *     import "github.com/deatil/lakego-doak/lakego/command"
 *     str, err := command.Call("lakego-admin:reset-permission")
 *
 * @create 2021-9-25
 * @author deatil
 */
func Call(name string, params ...string) (string, error) {
    path := CommandLookPath()

    newParams := []string{
        name,
    }

    newParams = append(newParams, params...)

    return Commands(path, newParams...)
}

// 脚本文件
func Commands(commandName string, params ...string) (string, error) {
    cmd := exec.Command(commandName, params...)

    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = os.Stderr

    // 重定目录
    // cmd.Dir = commandDir

    err := cmd.Start()
    if err != nil {
        return "", err
    }

    err = cmd.Wait()

    return out.String(), err
}

// 可执行文件的绝对路径
func CommandLookPath() string {
    // 可执行文件的绝对路径
    path, _ := exec.LookPath(os.Args[0])

    // 绝对路径
    absPath, _ := filepath.Abs(path)

    // 索引
    // index := strings.LastIndex(absPath, string(os.PathSeparator))
    // path2 := path[:index]

    return absPath
}

