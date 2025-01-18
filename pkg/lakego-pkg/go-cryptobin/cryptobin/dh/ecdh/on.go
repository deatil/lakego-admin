package ecdh

// 引出错误信息
func (this ECDH) OnError(fn func([]error)) ECDH {
    fn(this.Errors)

    return this
}

