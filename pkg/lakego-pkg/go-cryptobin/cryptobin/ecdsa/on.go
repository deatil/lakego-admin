package ecdsa

type (
    // 错误方法
    EcdsaErrorFunc = func([]error)
)

// 引出错误信息
func (this Ecdsa) OnError(fn EcdsaErrorFunc) Ecdsa {
    fn(this.Errors)

    return this
}

