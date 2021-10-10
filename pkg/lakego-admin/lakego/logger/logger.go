package logger

import (
    "time"

    "github.com/pkg/errors"
    "github.com/sirupsen/logrus"
    "github.com/lestrrat/go-file-rotatelogs"

    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/logger/formatter"
)

/**
 * 日志
 *
 * import "github.com/deatil/lakego-admin/lakego/logger"
 *
 * @create 2021-9-8
 * @author deatil
 */
var log = logrus.New()

type Fields map[string]interface{}

// 默认设置
func init() {
    setting()
}

// 设置
func setting() {
    // 配置
    conf := config.New("logger")

    log.SetReportCaller(true)

    formatterType := conf.GetString("Formatter")

    var useFormatter logrus.Formatter
    if formatterType == "json" {
        useFormatter = formatter.JSONFormatter()
    } else if formatterType == "text" {
        useFormatter = formatter.TextFormatter()
    } else {
        useFormatter = formatter.NormalFormatter()
    }

    // 设置输出样式
    log.SetFormatter(useFormatter)

    // 日志目录
    filepath := conf.GetString("Filepath")

    // 日志文件
    baseLogPath := path.FormatPath(filepath)

    maxAge := conf.GetDuration("MaxAge")
    rotationTime := conf.GetDuration("RotationTime")

    writer, err := rotatelogs.New(
        baseLogPath + "/log_%Y%m%d.log",
        // rotatelogs.WithLinkName(baseLogPath), // 生成软链，指向最新日志文件
        rotatelogs.WithMaxAge(maxAge * time.Hour), // 文件最大保存时间
        rotatelogs.WithRotationTime(rotationTime * time.Hour), // 日志切割时间间隔
    )
    if err != nil {
        log.Errorf("config local file system logger error. %v", errors.WithStack(err))
    }

    // os.Stdout || os.Stderr
    // 设置output,默认为stderr,可以为任何io.Writer，比如文件*os.File
    // file, _ := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    log.SetOutput(writer)

    // 设置最低loglevel
    log.SetLevel(logrus.TraceLevel)
}

// 设置自定义变量
func WithFields(fields Fields) *logrus.Entry {
    data := make(logrus.Fields, len(fields))
    for k, v := range fields {
        data[k] = v
    }

    return log.WithFields(data)
}

func Trace(args ...interface{}) {
    log.Trace(args...)
}

func Tracef(template string, args ...interface{}) {
    log.Tracef(template, args...)
}

func Debug(args ...interface{}) {
    log.Debug(args...)
}

func Debugf(template string, args ...interface{}) {
    log.Debugf(template, args...)
}

func Info(args ...interface{}) {
    log.Info(args...)
}

func Infof(template string, args ...interface{}) {
    log.Infof(template, args...)
}

func Warn(args ...interface{}) {
    log.Warn(args...)
}

func Warnf(template string, args ...interface{}) {
    log.Warnf(template, args...)
}

func Error(args ...interface{}) {
    log.Error(args...)
}

func Errorf(template string, args ...interface{}) {
    log.Errorf(template, args...)
}

func Fatal(args ...interface{}) {
    log.Fatal(args...)
}

func Fatalf(template string, args ...interface{}) {
    log.Fatalf(template, args...)
}

func Panic(args ...interface{}) {
    log.Panic(args...)
}

func Panicf(template string, args ...interface{}) {
    log.Panicf(template, args...)
}
