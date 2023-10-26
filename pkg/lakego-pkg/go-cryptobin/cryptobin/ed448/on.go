package ed448

type (
    // 错误方法
    EdDSAErrorFunc = func([]error)
)

// 引出错误信息
func (this ED448) OnError(fn EdDSAErrorFunc) ED448 {
    fn(this.Errors)

    return this
}

