package cmd

import (
    "io"
    "os"
    "os/exec"
    "syscall"
    "time"
)

/**
 *
    pid = cmd.Process.Pid

    _, err = cmd.Process.Wait()
    if err != nil {
        return pid, err
    }
 *
 */
func (this *Cmd) Kill(pid int) (int, error) {
    var err error

    if this.SendInterrupt {
        if err = syscall.Kill(pid, syscall.SIGINT); err != nil {
            return 0, err
        }

        time.Sleep(this.KillDelay * time.Millisecond)
    }

    err = this.KillByPid(pid)
    if err != nil {
        return pid, err
    }

    return pid, nil
}

func (this *Cmd) Start(cmd string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
    c := exec.Command("/bin/sh", "-c", cmd)

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
