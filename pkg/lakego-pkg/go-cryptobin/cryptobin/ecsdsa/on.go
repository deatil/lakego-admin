package ecsdsa

// 引出错误信息
func (this ECSDSA) OnError(fn func([]error)) ECSDSA {
    fn(this.Errors)

    return this
}

