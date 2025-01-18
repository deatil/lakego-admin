package rsa

// 引出错误信息
func (this RSA) OnError(fn func([]error)) RSA {
    fn(this.Errors)

    return this
}

