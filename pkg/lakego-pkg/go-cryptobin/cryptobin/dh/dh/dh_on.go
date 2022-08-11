package dh

type (
    // 错误方法
    ErrorFunc = func([]error)
)

// 引出错误信息
func (this Dh) OnError(fn ErrorFunc) Dh {
    fn(this.Errors)

    return this
}

