package ecsdsa

type (
    // 错误方法
    EcgdsaErrorFunc = func([]error)
)

// 引出错误信息
func (this ECSDSA) OnError(fn EcgdsaErrorFunc) ECSDSA {
    fn(this.Errors)

    return this
}

