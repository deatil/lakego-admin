package normal

import (
    "bytes"
    "fmt"
    "encoding/json"

    "github.com/sirupsen/logrus"
)

/**
 * 正常格式化
 *
 * @create 2021-9-8
 * @author deatil
 */
type NormalFormatter struct {}

func (this *NormalFormatter) Format(entry *logrus.Entry) ([]byte, error){
    var b *bytes.Buffer
    if entry.Buffer != nil {
        b = entry.Buffer
    } else {
        b = &bytes.Buffer{}
    }

    timestamp := entry.Time.Format("2006-01-02 15:04:05")
    var newLog string

    /*
    entry.Caller.File：文件名
    entry.Caller.Line: 行号
    entry.Caller.Function：函数名
    entry.Caller 中还有调用栈相关信息，有需要可以在日志中加入
    entry.HasCaller() 的判断是必须的，否则如果外部没有设置logrus.SetReportCaller(true)，entry.Caller.*的调用会引发Panic

    fName := entry.Caller.File
    newLog = fmt.Sprintf(
        "[%s] [%s] [%s:%d %s] %s %s\n",
        timestamp, entry.Level,
        fName, entry.Caller.Line, entry.Caller.Function,
        data, entry.Message,
    )
    */


    var data []byte
    if len(entry.Data) > 0 {
        data, _ = json.Marshal(entry.Data)
    } else {
        data = []byte("")
    }

    // HasCaller() 为 true 才会有调用信息
    if entry.HasCaller() {
        newLog = fmt.Sprintf("[%s] [%s] %s %s\n", timestamp, entry.Level, entry.Message, data)
    } else{
        newLog = fmt.Sprintf("[%s] [%s] %s %s\n", timestamp, entry.Level, entry.Message, data)
    }

    b.WriteString(newLog)
    return b.Bytes(), nil
}
