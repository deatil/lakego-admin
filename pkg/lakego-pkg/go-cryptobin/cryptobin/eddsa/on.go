package eddsa

// 引出错误信息
func (this EdDSA) OnError(fn func([]error)) EdDSA {
    fn(this.Errors)

    return this
}

