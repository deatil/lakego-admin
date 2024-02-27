package gost

type (
    // 错误方法
    DSAErrorFunc = func([]error)
)

// 引出错误信息
func (this Gost) OnError(fn DSAErrorFunc) Gost {
    fn(this.Errors)

    return this
}

