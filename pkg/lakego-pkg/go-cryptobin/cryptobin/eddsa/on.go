package eddsa

type (
    // 错误方法
    EdDSAErrorFunc = func([]error)
)

// 引出错误信息
func (this EdDSA) OnError(fn EdDSAErrorFunc) EdDSA {
    fn(this.Errors)

    return this
}

