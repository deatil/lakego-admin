package curve25519

// 引出错误信息
func (this Curve25519) OnError(fn func([]error)) Curve25519 {
    fn(this.Errors)

    return this
}

