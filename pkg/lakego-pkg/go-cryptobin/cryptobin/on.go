package cryptobin

type (
    // 错误方法
    ErrorFunc = func(error)
)

// 引出错误信息
func (this Cryptobin) OnError(fn ErrorFunc) Cryptobin {
    fn(this.Error)

    return this
}

