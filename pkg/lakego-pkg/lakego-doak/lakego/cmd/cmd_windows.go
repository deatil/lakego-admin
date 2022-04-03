package cmd

import (
    "io"
    "log"
    "os"
    "os/exec"
    "strconv"
    "strings"
)

func (this *Cmd) Kill(pid int) (int, error) {
    kill := exec.Command("TASKKILL", "/T", "/F", "/PID", strconv.Itoa(pid))

    return pid, kill.Run()
}

func (this *Cmd) Start(cmd string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
    var err error

    if !strings.Contains(cmd, ".exe") {
        log.Printf("CMD will not recognize non .exe file for execution, path: %s", cmd)
    }

    c := exec.Command("cmd", "/c", cmd)
    stderr, err := c.StderrPipe()
    if err != nil {
        return nil, nil, nil, nil, err
    }

    stdout, err := c.StdoutPipe()
    if err != nil {
        return nil, nil, nil, nil, err
    }

    stdin, err := c.StdinPipe()
    if err != nil {
        return nil, nil, nil, nil, err
    }

    c.Stdout = os.Stdout
    c.Stderr = os.Stderr
    c.Stdin = os.Stdin

    err = c.Start()
    if err != nil {
        return nil, nil, nil, nil, err
    }

    return c, stdin, stdout, stderr, nil
}
