package logger

import (
    "github.com/deatil/lakego-admin/lakego/logger/interfaces"
)

// 构造方法
func New(driver interfaces.Driver) *Logger {
    logger := &Logger{}

    return logger.WithDriver(driver)
}

// 变量
type Fields map[string]interface{}

/**
 * 日志
 *
 * import "github.com/deatil/lakego-admin/lakego/logger"
 *
 * @create 2021-11-3
 * @author deatil
 */
type Logger struct {
    // 日志驱动
    Driver interfaces.Driver
}

// 设置驱动
func (this *Logger) WithDriver(driver interfaces.Driver) *Logger {
    this.Driver = driver

    return this
}

// 获取驱动
func (this *Logger) GetDriver() interfaces.Driver {
    return this.Driver
}

func (this *Logger) Trace(args ...interface{}) {
    this.Driver.Trace(args...)
}

func (this *Logger) Tracef(template string, args ...interface{}) {
    this.Driver.Tracef(template, args...)
}

func (this *Logger) Debug(args ...interface{}) {
    this.Driver.Debug(args...)
}

func (this *Logger) Debugf(template string, args ...interface{}) {
    this.Driver.Debugf(template, args...)
}

func (this *Logger) Info(args ...interface{}) {
    this.Driver.Info(args...)
}

func (this *Logger) Infof(template string, args ...interface{}) {
    this.Driver.Infof(template, args...)
}

func (this *Logger) Warn(args ...interface{}) {
    this.Driver.Warn(args...)
}

func (this *Logger) Warnf(template string, args ...interface{}) {
    this.Driver.Warnf(template, args...)
}

func (this *Logger) Error(args ...interface{}) {
    this.Driver.Error(args...)
}

func (this *Logger) Errorf(template string, args ...interface{}) {
    this.Driver.Errorf(template, args...)
}

func (this *Logger) Fatal(args ...interface{}) {
    this.Driver.Fatal(args...)
}

func (this *Logger) Fatalf(template string, args ...interface{}) {
    this.Driver.Fatalf(template, args...)
}

func (this *Logger) Panic(args ...interface{}) {
    this.Driver.Panic(args...)
}

func (this *Logger) Panicf(template string, args ...interface{}) {
    this.Driver.Panicf(template, args...)
}
