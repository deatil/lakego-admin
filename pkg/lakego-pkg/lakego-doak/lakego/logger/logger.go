package logger

import (
    "github.com/deatil/lakego-doak/lakego/logger/interfaces"
)

// 构造方法
func New(driver interfaces.Driver) *Logger {
    logger := &Logger{}

    return logger.WithDriver(driver)
}

// 变量
type Fields map[string]any

/**
 * 日志
 *
 * import "github.com/deatil/lakego-doak/lakego/logger"
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

// 批量设置自定义变量
func (this *Logger) WithFields(fields map[string]any) any {
    return this.Driver.WithFields(fields)
}

// 设置自定义变量
func (this *Logger) WithField(key string, value any) any {
    return this.Driver.WithField(key, value)
}

// ========

func (this *Logger) Trace(args ...any) {
    this.Driver.Trace(args...)
}

func (this *Logger) Debug(args ...any) {
    this.Driver.Debug(args...)
}

func (this *Logger) Info(args ...any) {
    this.Driver.Info(args...)
}

func (this *Logger) Warn(args ...any) {
    this.Driver.Warn(args...)
}

func (this *Logger) Warning(args ...any) {
    this.Driver.Warning(args...)
}

func (this *Logger) Error(args ...any) {
    this.Driver.Error(args...)
}

func (this *Logger) Fatal(args ...any) {
    this.Driver.Fatal(args...)
}

func (this *Logger) Panic(args ...any) {
    this.Driver.Panic(args...)
}

// ========

func (this *Logger) Tracef(template string, args ...any) {
    this.Driver.Tracef(template, args...)
}

func (this *Logger) Debugf(template string, args ...any) {
    this.Driver.Debugf(template, args...)
}

func (this *Logger) Infof(template string, args ...any) {
    this.Driver.Infof(template, args...)
}

func (this *Logger) Warnf(template string, args ...any) {
    this.Driver.Warnf(template, args...)
}

func (this *Logger) Warningf(template string, args ...any) {
    this.Driver.Warningf(template, args...)
}

func (this *Logger) Errorf(template string, args ...any) {
    this.Driver.Errorf(template, args...)
}

func (this *Logger) Fatalf(template string, args ...any) {
    this.Driver.Fatalf(template, args...)
}

func (this *Logger) Panicf(template string, args ...any) {
    this.Driver.Panicf(template, args...)
}
