package ecgdsa

// 引出错误信息
func (this ECGDSA) OnError(fn func([]error)) ECGDSA {
    fn(this.Errors)

    return this
}

