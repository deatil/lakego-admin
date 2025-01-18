package bign

// 引出错误信息
func (this Bign) OnError(fn func([]error)) Bign {
    fn(this.Errors)

    return this
}

