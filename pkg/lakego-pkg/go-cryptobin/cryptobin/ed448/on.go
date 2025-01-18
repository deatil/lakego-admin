package ed448

// 引出错误信息
func (this ED448) OnError(fn func([]error)) ED448 {
    fn(this.Errors)

    return this
}

