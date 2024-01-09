package logrus

import (
    "fmt"
    "time"
    logger "log"

    "github.com/sirupsen/logrus"
    "github.com/lestrrat/go-file-rotatelogs"

    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/logger/driver/logrus/formatter"
)

// 构造方法
func New() *Logrus {
    return &Logrus{}
}

type (
    // 日志额外数据
    Fields = logrus.Fields

    // Entry 别名
    Entry = logrus.Entry

    // 日志方法
    LogFunction = logrus.LogFunction
)

/**
 * 日志 logrus 驱动
 *
 * @create 2021-11-3
 * @author deatil
 */
type Logrus struct {
    // 配置
    Config map[string]any
}

// 设置配置
func (this *Logrus) WithConfig(config map[string]any) {
    this.Config = config
}

// 批量设置自定义变量
func (this *Logrus) WithFields(fields map[string]any) any {
    data := make(Fields, len(fields))
    for k, v := range fields {
        data[k] = v
    }

    return this.getLogger().WithFields(data)
}

// 设置自定义变量
// *logrus.Entry
func (this *Logrus) WithField(key string, value any) any {
    return this.getLogger().WithField(key, value)
}

// ========

func (this *Logrus) Trace(args ...any) {
    this.getLogger().Trace(args...)
}

func (this *Logrus) Debug(args ...any) {
    this.getLogger().Debug(args...)
}

func (this *Logrus) Info(args ...any) {
    this.getLogger().Info(args...)
}

func (this *Logrus) Warn(args ...any) {
    this.getLogger().Warn(args...)
}

func (this *Logrus) Warning(args ...any) {
    this.getLogger().Warning(args...)
}

func (this *Logrus) Error(args ...any) {
    this.getLogger().Error(args...)
}

func (this *Logrus) Fatal(args ...any) {
    this.getLogger().Fatal(args...)
}

func (this *Logrus) Panic(args ...any) {
    this.getLogger().Panic(args...)
}

// ========

func (this *Logrus) Tracef(template string, args ...any) {
    this.getLogger().Tracef(template, args...)
}

func (this *Logrus) Debugf(template string, args ...any) {
    this.getLogger().Debugf(template, args...)
}

func (this *Logrus) Infof(template string, args ...any) {
    this.getLogger().Infof(template, args...)
}

func (this *Logrus) Warnf(template string, args ...any) {
    this.getLogger().Warnf(template, args...)
}

func (this *Logrus) Warningf(template string, args ...any) {
    this.getLogger().Warningf(template, args...)
}

func (this *Logrus) Errorf(template string, args ...any) {
    this.getLogger().Errorf(template, args...)
}

func (this *Logrus) Fatalf(template string, args ...any) {
    this.getLogger().Fatalf(template, args...)
}

func (this *Logrus) Panicf(template string, args ...any) {
    this.getLogger().Panicf(template, args...)
}

// ========

func (this *Logrus) Traceln(args ...any) {
    this.getLogger().Traceln(args...)
}

func (this *Logrus) Debugln(args ...any) {
    this.getLogger().Debugln(args...)
}

func (this *Logrus) Infoln(args ...any) {
    this.getLogger().Infoln(args...)
}

func (this *Logrus) Println(args ...any) {
    this.getLogger().Println(args...)
}

func (this *Logrus) Warnln(args ...any) {
    this.getLogger().Warnln(args...)
}

func (this *Logrus) Warningln(args ...any) {
    this.getLogger().Warningln(args...)
}

func (this *Logrus) Errorln(args ...any) {
    this.getLogger().Errorln(args...)
}

func (this *Logrus) Fatalln(args ...any) {
    this.getLogger().Fatalln(args...)
}

func (this *Logrus) Panicln(args ...any) {
    this.getLogger().Panicln(args...)
}

// ========

func (this *Logrus) TraceFn(fn LogFunction) {
    this.getLogger().TraceFn(fn)
}

func (this *Logrus) DebugFn(fn LogFunction) {
    this.getLogger().DebugFn(fn)
}

func (this *Logrus) InfoFn(fn LogFunction) {
    this.getLogger().InfoFn(fn)
}

func (this *Logrus) PrintFn(fn LogFunction) {
    this.getLogger().PrintFn(fn)
}

func (this *Logrus) WarnFn(fn LogFunction) {
    this.getLogger().WarnFn(fn)
}

func (this *Logrus) WarningFn(fn LogFunction) {
    this.getLogger().WarningFn(fn)
}

func (this *Logrus) ErrorFn(fn LogFunction) {
    this.getLogger().ErrorFn(fn)
}

func (this *Logrus) FatalFn(fn LogFunction) {
    this.getLogger().FatalFn(fn)
}

func (this *Logrus) PanicFn(fn LogFunction) {
    this.getLogger().PanicFn(fn)
}

// ========

func (this *Logrus) Exit(code int) {
    this.getLogger().Exit(code)
}

// 获取等级
func (this *Logrus) GetLevel() logrus.Level {
    return this.getLogger().GetLevel()
}

// 设置
func (this *Logrus) getLogger() *logrus.Logger {
    // 配置
    conf := this.Config

    log := logrus.New()

    log.SetReportCaller(true)

    var useFormatter logrus.Formatter

    formatterType := conf["formatter"].(string)
    switch formatterType {
        case "json":
            // json 格式
            useFormatter = formatter.JSONFormatter()

        case "text":
            // 文档格式
            useFormatter = formatter.TextFormatter()

        default:
            // 正常格式
            useFormatter = formatter.NormalFormatter()
    }

    // 设置输出样式
    log.SetFormatter(useFormatter)

    // 日志目录
    filepath := conf["filepath"].(string)

    // 日志文件
    // log_%Y%m%d.log
    logPath := path.FormatPath(filepath)

    maxAge := time.Duration(int64(conf["max-age"].(int)))
    rotationTime := time.Duration(int64(conf["rotation-time"].(int)))

    writer, err := rotatelogs.New(
        logPath,
        // rotatelogs.WithLinkName(baseLogPath), // 生成软链，指向最新日志文件
        rotatelogs.WithMaxAge(maxAge * time.Hour), // 文件最大保存时间
        rotatelogs.WithRotationTime(rotationTime * time.Hour), // 日志切割时间间隔
    )
    if err != nil {
        logger.Print(fmt.Sprintf("日志配置错误：%v", err))
    }

    // os.Stdout || os.Stderr
    // 设置output,默认为stderr,可以为任何io.Writer，比如文件*os.File
    // file, _ := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    log.SetOutput(writer)

    // 日志等级
    level := conf["level"].(string)

    // 设置最低 loglevel
    switch level {
        case "panic":
            // panic 等级
            log.SetLevel(logrus.PanicLevel)

        case "fatal":
            // fatal 等级
            log.SetLevel(logrus.FatalLevel)

        case "error":
            // error 等级
            log.SetLevel(logrus.ErrorLevel)

        case "warning":
            // warning 等级
            log.SetLevel(logrus.WarnLevel)

        case "info":
            // info 等级
            log.SetLevel(logrus.InfoLevel)

        case "debug":
            // debug 等级
            log.SetLevel(logrus.DebugLevel)

        case "trace":
            // trace 等级
            log.SetLevel(logrus.TraceLevel)
    }

    return log
}

