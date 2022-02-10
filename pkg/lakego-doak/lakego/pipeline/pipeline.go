package pipeline

// 构造函数
func New() *Pipeline {
    return NewPipeline()
}

// 构造函数
func NewPipeline() *Pipeline {
    return &Pipeline{}
}

type (
    // 管道单个
    PipeItem = interface{}

    // 管道数组
    PipeArray = []PipeItem

    // Next 函数
    NextFunc = func(interface{}) interface{}

    // 目标函数
    DestinationFunc = func(interface{}) interface{}

    // 迭代的值函数
    PipeFunc = func(interface{}, NextFunc) interface{}

    // carry 函数
    CarryFunc = func(interface{}, interface{}) interface{}

    // carry 回调函数
    CarryCallbackFunc = func(interface{}) interface{}

    // 报错回调函数
    ExceptionCallbackFunc = func(interface{}, interface{}, interface{})
)

// 管道接口
type PipeInterface interface {
    // 方法
    Handle(interface{}, NextFunc) interface{}
}

/**
 * 管道
 *
 * @create 2022-2-8
 * @author deatil
 */
type Pipeline struct {
    // 数据
    Passable interface{}

    // 管道
    Pipes PipeArray

    // Carry 回调函数
    CarryCallback CarryCallbackFunc

    // Exception 回调函数
    ExceptionCallback ExceptionCallbackFunc
}

// 设置数据
func (this *Pipeline) Send(passable interface{}) *Pipeline {
    this.Passable = passable

    return this
}

// 设置管道
func (this *Pipeline) Through(pipes ...PipeItem) *Pipeline {
    this.Pipes = pipes

    return this
}

// 数组
func (this *Pipeline) ThroughArray(pipes PipeArray) *Pipeline {
    this.Pipes = pipes

    return this
}

// 返回
func (this *Pipeline) Then(destination DestinationFunc) interface{} {
    pipeline := ArrayReduce(
        ArrayReverse(this.Pipes),
        this.Carry(),
        this.PrepareDestination(destination),
    )

    newPipeline := pipeline.(NextFunc)

    return newPipeline(this.Passable)
}

// 返回数据
func (this *Pipeline) ThenReturn() interface{} {
    return this.Then(func(passable interface{}) interface{} {
        return passable
    })
}

// 包装
func (this *Pipeline) PrepareDestination(destination DestinationFunc) NextFunc {
    return func(passable interface{}) interface{} {
        return destination(passable)
    }
}

// 格式化数据
func (this *Pipeline) Carry() CarryFunc {
    return func(stack interface{}, pipe interface{}) interface{} {
        newStack := stack.(NextFunc)

        return func(passable interface{}) interface{} {

            // 判断类型
            switch pipe.(type) {
                // 回调方法
                case PipeFunc:
                    newPipe := pipe.(PipeFunc)
                    return newPipe(passable, newStack)

                // 结构体
                case PipeInterface:
                    newPipe := pipe.(PipeInterface)
                    carry := newPipe.Handle(passable, newStack)

                    return this.HandleCarry(carry)

                // 默认报错
                default:
                    this.HandleException(passable, pipe, newStack)
                    return nil
            }

        }
    }
}

// 获取设置的管道
func (this *Pipeline) GetPipes() PipeArray {
    return this.Pipes
}

// 返回数据
func (this *Pipeline) HandleCarry(carry interface{}) interface{} {
    if this.CarryCallback != nil {
        callbackFunc := this.CarryCallback

        return callbackFunc(carry)
    }

    return carry
}

// 报错信息
func (this *Pipeline) HandleException(passable interface{}, pipe interface{}, stack interface{}) {
    if this.ExceptionCallback != nil {
        callbackFunc := this.ExceptionCallback

        callbackFunc(passable, pipe, stack)
        return
    }

    panic("管道队列中有格式设置错误")
}

// 设置 Carry 回调函数
func (this *Pipeline) WithCarryCallback(callback CarryCallbackFunc) *Pipeline {
    this.CarryCallback = callback

    return this
}

// 设置 Exception 回调函数
func (this *Pipeline) WithExceptionCallback(callback ExceptionCallbackFunc) *Pipeline {
    this.ExceptionCallback = callback

    return this
}
