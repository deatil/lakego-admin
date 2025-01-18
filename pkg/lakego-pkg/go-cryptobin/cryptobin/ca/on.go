package ca

// 引出错误信息
func (this CA) OnError(fn func([]error)) CA {
    fn(this.Errors)

    return this
}

