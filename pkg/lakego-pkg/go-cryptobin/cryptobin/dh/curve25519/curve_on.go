package curve25519

type (
    // 错误方法
    ErrorFunc = func([]error)
)

// 引出错误信息
func (this Curve25519) OnError(fn ErrorFunc) Curve25519 {
    fn(this.Errors)

    return this
}

