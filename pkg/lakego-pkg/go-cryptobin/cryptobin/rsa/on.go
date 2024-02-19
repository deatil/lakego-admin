package rsa

type (
    // 错误方法
    RsaErrorFunc = func([]error)
)

// 引出错误信息
func (this RSA) OnError(fn RsaErrorFunc) RSA {
    fn(this.Errors)

    return this
}

