package datebin

type (
	// 错误方法
	// Error Func
	ErrorFunc = func([]error)
)

// 错误信息
// on Error with Error Func
func (this Datebin) OnError(fn ErrorFunc) Datebin {
	fn(this.Errors)

	return this
}
