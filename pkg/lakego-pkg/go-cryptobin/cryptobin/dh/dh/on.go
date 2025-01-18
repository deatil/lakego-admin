package dh

// 引出错误信息
func (this DH) OnError(fn func([]error)) DH {
    fn(this.Errors)

    return this
}

