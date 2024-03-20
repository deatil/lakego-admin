package schedule

import (
    "github.com/deatil/lakego-doak/lakego/facade"
)

// 构造函数
func NewLogger() Logger {
    return Logger{}
}

/**
 * 日志
 *
 * @create 2022-12-2
 * @author deatil
 */
type Logger struct {}

// 实现接口
func (this Logger) Printf(msg string, v ...any) {
    msg = "schedule: " + msg

    facade.Logger.Errorf(msg, v...)
}
