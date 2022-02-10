package formatter

import (
    "path"
    "runtime"
    "github.com/sirupsen/logrus"
    "github.com/deatil/lakego-doak/lakego/logger/driver/logrus/formatter/normal"
)

// 正常存储格式
func NormalFormatter() logrus.Formatter {
    formatter := &normal.NormalFormatter{}

    return formatter
}

// 文本存储格式
func TextFormatter() logrus.Formatter {
    formatter := &logrus.TextFormatter{
        // 以下设置只是为了使输出更美观
        DisableColors: true,

        // 时间格式化
        TimestampFormat: "2006-01-02 15:03:04",
    }

    return formatter
}

// json 存储格式
func JSONFormatter() logrus.Formatter {
    formatter := &logrus.JSONFormatter{
        TimestampFormat:"2006-01-02 15:03:04",

        CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
            //处理文件名
            fileName := path.Base(frame.File)
            return frame.Function, fileName
        },
    }

    return formatter
}
