package logger

import (
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/lestrrat/go-file-rotatelogs"

	"lakego-admin/lakego/config"
	"lakego-admin/lakego/support/path"
	"lakego-admin/lakego/logger/formatter"
)

type Fields map[string]interface{}

// import "lakego-admin/lakego/logger"
func init() {
	log.SetReportCaller(true)
	
    // 设置输出样式，自带的只有两种样式 logrus.JSONFormatter{} 和 logrus.TextFormatter{}
    log.SetFormatter(new(formatter.NormalFormatter))
	
	conf := config.NewConfig("logger")
	
	// 日志目录
	filepath := conf.GetString("Filepath")
	
	// 日志文件
	baseLogPath := path.GetBasePath() + filepath
	
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
    log.SetLevel(log.TraceLevel)
}

// 设置自定义变量
func WithFields(fields Fields) *log.Entry {
	data := make(log.Fields, len(fields))
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
