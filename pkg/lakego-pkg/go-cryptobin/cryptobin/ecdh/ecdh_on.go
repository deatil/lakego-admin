package ecdh

type (
    // 错误方法
    ErrorFunc = func([]error)
)

// 引出错误信息
func (this Ecdh) OnError(fn ErrorFunc) Ecdh {
    fn(this.Errors)

    return this
}

