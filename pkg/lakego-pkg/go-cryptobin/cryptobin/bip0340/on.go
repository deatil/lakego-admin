package bip0340

type (
    // 错误方法
    Bip0340ErrorFunc = func([]error)
)

// 引出错误信息
func (this BIP0340) OnError(fn Bip0340ErrorFunc) BIP0340 {
    fn(this.Errors)

    return this
}

