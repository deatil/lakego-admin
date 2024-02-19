package ecdsa

type (
    // 错误方法
    EcdsaErrorFunc = func([]error)
)

// 引出错误信息
func (this ECDSA) OnError(fn EcdsaErrorFunc) ECDSA {
    fn(this.Errors)

    return this
}

