package cryptobin

type (
    // 错误方法
    CAErrorFunc = func(error)
)

// 引出错误信息
func (this CA) OnError(fn CAErrorFunc) CA {
    fn(this.Error)

    return this
}

