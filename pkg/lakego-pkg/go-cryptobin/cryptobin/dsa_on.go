package cryptobin

type (
    // 错误方法
    DSAErrorFunc = func(error)
)

// 引出错误信息
func (this DSA) OnError(fn DSAErrorFunc) DSA {
    fn(this.Error)

    return this
}

