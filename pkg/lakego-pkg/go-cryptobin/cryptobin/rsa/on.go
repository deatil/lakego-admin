package rsa

type (
    // 错误方法
    RsaErrorFunc = func([]error)
)

// 引出错误信息
func (this Rsa) OnError(fn RsaErrorFunc) Rsa {
    fn(this.Errors)

    return this
}

