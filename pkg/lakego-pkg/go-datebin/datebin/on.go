package datebin

type (
    // 错误方法
    ErrorFunc = func([]error)
)

// 引出错误信息
func (this Datebin) OnError(fn ErrorFunc) Datebin {
    fn(this.Errors)

    return this
}
