package crypto

type (
    // 错误方法
    // Error Func
    ErrorFunc = func([]error)
)

// 错误事件
// On Error
func (this Cryptobin) OnError(fn ErrorFunc) Cryptobin {
    this.errEvent = this.errEvent.On(fn)

    return this
}

// 触发错误事件
// trigger Error
func (this Cryptobin) triggerError() Cryptobin {
    this.errEvent.Trigger(this.Errors)

    return this
}

