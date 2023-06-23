package elgamal

type (
    // 错误方法
    DSAErrorFunc = func([]error)
)

// 引出错误信息
func (this EIGamal) OnError(fn DSAErrorFunc) EIGamal {
    fn(this.Errors)

    return this
}

