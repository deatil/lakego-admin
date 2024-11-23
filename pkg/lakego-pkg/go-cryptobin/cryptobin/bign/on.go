package bign

type (
    // 错误方法
    EcgdsaErrorFunc = func([]error)
)

// 引出错误信息
func (this Bign) OnError(fn EcgdsaErrorFunc) Bign {
    fn(this.Errors)

    return this
}

