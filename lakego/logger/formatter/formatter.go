package formatter

import (
    "bytes"
    "fmt"
    "encoding/json"
    
    "github.com/sirupsen/logrus"
)

// 正常格式化
type NormalFormatter struct {

}

func (m *NormalFormatter) Format(entry *logrus.Entry) ([]byte, error){
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
    */
    
    var data []byte
    if len(entry.Data) > 0 {
        data, _ = json.Marshal(entry.Data)
    } else {
        data = []byte("")
    }
    
    // HasCaller()为true才会有调用信息
    if entry.HasCaller() {
        fName := entry.Caller.File
        newLog = fmt.Sprintf(
            "[%s] [%s] [%s:%d %s] %s %s\n",
            timestamp, 
            entry.Level, 
            fName, 
            entry.Caller.Line, 
            entry.Caller.Function, 
            data,
            entry.Message,
        )
    } else{
        newLog = fmt.Sprintf("[%s] [%s] %s %s\n", timestamp, entry.Level, data, entry.Message)
    }
    
    b.WriteString(newLog)
    return b.Bytes(), nil
}

/*
logrus.SetFormatter(&logrus.JSONFormatter{
    TimestampFormat:"2006-01-02 15:03:04",

    CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
        //处理文件名
        fileName := path.Base(frame.File)
        return frame.Function, fileName
    },
})

---

func main(){
    logrus.SetReportCaller(true)
    logrus.SetFormatter(&logrus.TextFormatter{
        //以下设置只是为了使输出更美观
        DisableColors:true,
        TimestampFormat:"2006-01-02 15:03:04",
    })

    Demo()
}
*/
