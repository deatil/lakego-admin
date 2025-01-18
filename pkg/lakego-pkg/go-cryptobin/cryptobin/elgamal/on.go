package elgamal

// 引出错误信息
func (this ElGamal) OnError(fn func([]error)) ElGamal {
    fn(this.Errors)

    return this
}

