package ecgdsa

type (
    // 错误方法
    EcgdsaErrorFunc = func([]error)
)

// 引出错误信息
func (this SSH) OnError(fn EcgdsaErrorFunc) SSH {
    fn(this.Errors)

    return this
}

