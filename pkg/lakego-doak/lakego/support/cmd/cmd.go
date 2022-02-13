package cmd

import (
    "os"
    "fmt"
    "sync"
    "time"
)

// 构造函数
func New() *Cmd {
    return &Cmd{
        SendInterrupt: false,
        KillDelay: 15,
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

// 设置
func (this *Cmd) WithSendInterrupt(sendInterrupt bool) *Cmd {
    this.SendInterrupt = sendInterrupt

    return this
}

// 设置延迟时间
func (this *Cmd) WithKillDelay(killDelay time.Duration) *Cmd {
    this.KillDelay = killDelay

    return this
}

func (this *Cmd) KillByPid(pid int) error {
    proc, err := os.FindProcess(pid)
    if err != nil {
        return err
    }

    return proc.Kill()
}

func (this *Cmd) GetPid() string {
    return fmt.Sprintf("%d", os.Getpid())
}

func (this *Cmd) GetPpid() string {
    return fmt.Sprintf("%d", os.Getppid())
}

func (this *Cmd) WithLock(f func()) {
    this.mu.Lock()
    f()
    this.mu.Unlock()
}
