package elgamal

type (
    // 错误方法
    DSAErrorFunc = func([]error)
)

// 引出错误信息
func (this ElGamal) OnError(fn DSAErrorFunc) ElGamal {
    fn(this.Errors)

    return this
}

