package gost

// 引出错误信息
func (this Gost) OnError(fn func([]error)) Gost {
    fn(this.Errors)

    return this
}

