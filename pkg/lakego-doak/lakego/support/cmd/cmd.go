package cmd

import (
    "os"
    "fmt"
    "sync"
    "time"
)

// 构造函数
func New(sendInterrupt bool, killDelay time.Duration) *Cmd {
    return &Cmd{
        SendInterrupt: sendInterrupt,
        KillDelay: killDelay,
    }
}

/**
 * Cmd
 *
 * @create 2022-2-12
 * @author deatil
 */
type Cmd struct {
    // 锁定
    mu sync.RWMutex

    // 输出
    SendInterrupt bool

    // 延迟时间
    KillDelay time.Duration
}

func (this *Cmd) GetPid() string {
    return fmt.Sprintf("%d", os.Getpid())
}

func (this *Cmd) GetPpid() string {
    return fmt.Sprintf("%d", os.Getppid())
}

func (this *Cmd) KillByPid(pid int) error {
    proc, err := os.FindProcess(pid)
    if err != nil {
        return err
    }

    return proc.Kill()
}

func (this *Cmd) WithLock(f func()) {
    this.mu.Lock()
    f()
    this.mu.Unlock()
}
