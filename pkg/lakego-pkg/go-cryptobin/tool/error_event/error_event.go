package error_event

type (
    // 错误方法
    ErrorFunc = func([]error)
)

/**
 * 错误事件
 *
 * @create 2023-8-11
 * @author deatil
 */
type ErrorEvent struct {
    // 错误方法列表
    errorFuncs []ErrorFunc
}

// 构造函数
func New() ErrorEvent {
    e := ErrorEvent{
        errorFuncs: make([]ErrorFunc, 0),
    }

    return e
}

// 添加
func (this ErrorEvent) On(fn ErrorFunc) ErrorEvent {
    this.errorFuncs = append(this.errorFuncs, fn)

    return this
}

// 执行
func (this ErrorEvent) Trigger(errs []error) {
    if (len(this.errorFuncs) > 0) {
        for _, fn := range this.errorFuncs {
            fn(errs)
        }
    }
}
