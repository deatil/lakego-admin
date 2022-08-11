package sm2

type (
    // 错误方法
    SM2ErrorFunc = func([]error)
)

// 引出错误信息
func (this SM2) OnError(fn SM2ErrorFunc) SM2 {
    fn(this.Errors)

    return this
}

