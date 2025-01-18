package ecdsa

// 引出错误信息
func (this ECDSA) OnError(fn func([]error)) ECDSA {
    fn(this.Errors)

    return this
}

