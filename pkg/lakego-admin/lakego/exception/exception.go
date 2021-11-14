package exception

// 构造函数
func NewException() *Exception {
    e := &Exception{
        data: make(map[string]interface{}),
    }

    return e
}

/**
 * 存储异常
 *
 * @create 2021-11-13
 * @author deatil
 */
type Exception struct {
    // 数据
    data map[string]interface{}
}

// 设置
func (this *Exception) WithData(name string, data interface{}) *Exception {
    this.data[name] = data

    return this
}

// 批量设置
func (this *Exception) WithDatas(data map[string]interface{}) *Exception {
    if len(data) > 0 {
        for k, v := range data {
            this.WithData(k, v)
        }
    }

    return this
}

// 获取
func (this *Exception) GetData(name string) interface{} {
    if data, ok := this.data[name]; ok {
        return data
    }

    return nil
}

// 获取全部
func (this *Exception) GetDatas() map[string]interface{} {
    return this.data
}

// 设置文件信息
func (this *Exception) WithFile(data string) *Exception {
    return this.WithData("file", data)
}

// 获取文件信息
func (this *Exception) GetFile() string {
    data := this.GetData("file")

    if data != nil {
        return data.(string)
    }

    return ""
}

// 设置错误信息
func (this *Exception) WithMessage(data string) *Exception {
    return this.WithData("message", data)
}

// 获取错误信息
func (this *Exception) GetMessage() string {
    data := this.GetData("message")

    if data != nil {
        return data.(string)
    }

    return ""
}

// 设置堆栈信息
func (this *Exception) WithTrace(data []string) *Exception {
    return this.WithData("trace", data)
}

// 获取堆栈信息
func (this *Exception) GetTrace() []string {
    data := this.GetData("trace")

    if data != nil {
        return data.([]string)
    }

    return nil
}

