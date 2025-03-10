package logger

import (
    "github.com/deatil/lakego-doak/lakego/logger/interfaces"
)

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
    driver interfaces.Driver
}

// 构造方法
func New(driver interfaces.Driver) *Logger {
    logger := &Logger{}

    return logger.WithDriver(driver)
}

// 设置驱动
func (this *Logger) WithDriver(driver interfaces.Driver) *Logger {
    this.driver = driver

    return this
}

// 获取驱动
func (this *Logger) GetDriver() interfaces.Driver {
    return this.driver
}

// 批量设置自定义变量
func (this *Logger) WithFields(fields map[string]any) any {
    return this.driver.WithFields(fields)
}

// 设置自定义变量
func (this *Logger) WithField(key string, value any) any {
    return this.driver.WithField(key, value)
}

// ========

func (this *Logger) Trace(args ...any) {
    this.driver.Trace(args...)
}

func (this *Logger) Debug(args ...any) {
    this.driver.Debug(args...)
}

func (this *Logger) Info(args ...any) {
    this.driver.Info(args...)
}

func (this *Logger) Warn(args ...any) {
    this.driver.Warn(args...)
}

func (this *Logger) Warning(args ...any) {
    this.driver.Warning(args...)
}

func (this *Logger) Error(args ...any) {
    this.driver.Error(args...)
}

func (this *Logger) Fatal(args ...any) {
    this.driver.Fatal(args...)
}

func (this *Logger) Panic(args ...any) {
    this.driver.Panic(args...)
}

// ========

func (this *Logger) Tracef(template string, args ...any) {
    this.driver.Tracef(template, args...)
}

func (this *Logger) Debugf(template string, args ...any) {
    this.driver.Debugf(template, args...)
}

func (this *Logger) Infof(template string, args ...any) {
    this.driver.Infof(template, args...)
}

func (this *Logger) Warnf(template string, args ...any) {
    this.driver.Warnf(template, args...)
}

func (this *Logger) Warningf(template string, args ...any) {
    this.driver.Warningf(template, args...)
}

func (this *Logger) Errorf(template string, args ...any) {
    this.driver.Errorf(template, args...)
}

func (this *Logger) Fatalf(template string, args ...any) {
    this.driver.Fatalf(template, args...)
}

func (this *Logger) Panicf(template string, args ...any) {
    this.driver.Panicf(template, args...)
}
