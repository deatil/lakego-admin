package dsa

// 引出错误信息
func (this DSA) OnError(fn func([]error)) DSA {
    fn(this.Errors)

    return this
}

