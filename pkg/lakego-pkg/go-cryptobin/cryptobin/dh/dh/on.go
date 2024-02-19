package dh

type (
    // 错误方法
    ErrorFunc = func([]error)
)

// 引出错误信息
func (this DH) OnError(fn ErrorFunc) DH {
    fn(this.Errors)

    return this
}

