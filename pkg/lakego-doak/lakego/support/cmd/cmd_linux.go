package cmd

import (
    "io"
    "os"
    "os/exec"
    "syscall"
    "time"
)

func (this *Cmd) Kill(cmd *exec.Cmd) (pid int, err error) {
    pid = cmd.Process.Pid

    if this.SendInterrupt {
        if err = syscall.Kill(-pid, syscall.SIGINT); err != nil {
            return
        }

        time.Sleep(this.KillDelay * time.Millisecond)
    }

    pgid, err := syscall.Getpgid(cmd.Process.Pid)
    if err != nil {
        return pgid, err
    }

    if err = syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
        return pgid, err
    }

    _, err = cmd.Process.Wait()
    if err != nil {
        return pid, err
    }

    return
}

func (this *Cmd) Start(cmd string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
    c := exec.Command("/bin/sh", "-c", cmd)

    c.SysProcAttr = &syscall.SysProcAttr{
        Setpgid: true,
    }

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
