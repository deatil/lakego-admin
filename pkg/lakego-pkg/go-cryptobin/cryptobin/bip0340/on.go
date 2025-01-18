package bip0340

// 引出错误信息
func (this BIP0340) OnError(fn func([]error)) BIP0340 {
    fn(this.Errors)

    return this
}

