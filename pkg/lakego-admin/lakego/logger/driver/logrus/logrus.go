package logrus

import (
    "time"

    "github.com/pkg/errors"
    "github.com/sirupsen/logrus"
    "github.com/lestrrat/go-file-rotatelogs"

    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/logger/driver/logrus/formatter"
)

// 构造方法
func New() *Logrus {
    return &Logrus{}
}

// Entry 别名
type Entry = logrus.Entry

/**
 * 日志 logrus 驱动
 *
 * @create 2021-11-3
 * @author deatil
 */
type Logrus struct {
    // 配置
    Config map[string]interface{}
}

// 设置配置
func (this *Logrus) WithConfig(config map[string]interface{}) {
    this.Config = config
}

// 批量设置自定义变量
func (this *Logrus) WithFields(fields map[string]interface{}) interface{} {
    data := make(logrus.Fields, len(fields))
    for k, v := range fields {
        data[k] = v
    }

    return this.getLogger().WithFields(data)
}

// 设置自定义变量
// *logrus.Entry
func (this *Logrus) WithField(key string, value interface{}) interface{} {
    return this.getLogger().WithField(key, value)
}

func (this *Logrus) Trace(args ...interface{}) {
    this.getLogger().Trace(args...)
}

func (this *Logrus) Tracef(template string, args ...interface{}) {
    this.getLogger().Tracef(template, args...)
}

func (this *Logrus) Debug(args ...interface{}) {
    this.getLogger().Debug(args...)
}

func (this *Logrus) Debugf(template string, args ...interface{}) {
    this.getLogger().Debugf(template, args...)
}

func (this *Logrus) Info(args ...interface{}) {
    this.getLogger().Info(args...)
}

func (this *Logrus) Infof(template string, args ...interface{}) {
    this.getLogger().Infof(template, args...)
}

func (this *Logrus) Warn(args ...interface{}) {
    this.getLogger().Warn(args...)
}

func (this *Logrus) Warnf(template string, args ...interface{}) {
    this.getLogger().Warnf(template, args...)
}

func (this *Logrus) Error(args ...interface{}) {
    this.getLogger().Error(args...)
}

func (this *Logrus) Errorf(template string, args ...interface{}) {
    this.getLogger().Errorf(template, args...)
}

func (this *Logrus) Fatal(args ...interface{}) {
    this.getLogger().Fatal(args...)
}

func (this *Logrus) Fatalf(template string, args ...interface{}) {
    this.getLogger().Fatalf(template, args...)
}

func (this *Logrus) Panic(args ...interface{}) {
    this.getLogger().Panic(args...)
}

func (this *Logrus) Panicf(template string, args ...interface{}) {
    this.getLogger().Panicf(template, args...)
}

// 设置
func (this *Logrus) getLogger() *logrus.Logger {
    // 配置
    conf := this.Config

    log := logrus.New()

    log.SetReportCaller(true)

    formatterType := conf["formatter"].(string)

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
    filepath := conf["filepath"].(string)

    // 日志文件
    baseLogPath := path.FormatPath(filepath)

    maxAge := time.Duration(int64(conf["maxage"].(int)))
    rotationTime := time.Duration(int64(conf["rotationtime"].(int)))

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

    return log
}

