package ecgdsa

type (
    // 错误方法
    EcgdsaErrorFunc = func([]error)
)

// 引出错误信息
func (this ECGDSA) OnError(fn EcgdsaErrorFunc) ECGDSA {
    fn(this.Errors)

    return this
}

