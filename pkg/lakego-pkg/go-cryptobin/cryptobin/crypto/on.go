package crypto

type (
    // 错误方法
    ErrorFunc = func([]error)
)

// 添加错误事件
func (this Cryptobin) OnError(fn ErrorFunc) Cryptobin {
    this.errEvent = this.errEvent.On(fn)

    return this
}

// 触发
func (this Cryptobin) triggerError() Cryptobin {
    this.errEvent.Trigger(this.Errors)

    return this
}

