package pipeline

import(
    "reflect"
)

// 构造函数
func New() Pipeline {
    return NewPipeline()
}

// 构造函数
func NewPipeline() Pipeline {
    return Pipeline{
        Pipes: make([]PipeItem, 0),
    }
}

type (
    // 管道单个
    PipeItem = any

    // Next 函数
    NextFunc = func(any) any

    // 目标函数
    DestinationFunc = func(any) any

    // 迭代的值函数
    PipeFunc = func(any, NextFunc) any

    // carry 函数
    CarryFunc = func(any, any) any

    // carry 回调函数
    CarryCallbackFunc = func(any) any

    // 报错回调函数
    ExceptionCallbackFunc = func(any, any, any) any
)

// 管道接口
type PipeInterface interface {
    // 方法
    Handle(any, NextFunc) any
}

/**
 * 管道
 *
 * @create 2022-2-8
 * @author deatil
 */
type Pipeline struct {
    // 数据
    Passable any

    // 管道
    Pipes []PipeItem

    // 自定义方法
    Method string

    // Carry 回调函数
    CarryCallback CarryCallbackFunc

    // Exception 回调函数
    ExceptionCallback ExceptionCallbackFunc
}

// 设置数据
func (this Pipeline) Send(passable any) Pipeline {
    this.Passable = passable

    return this
}

// 设置管道
func (this Pipeline) Through(pipes ...PipeItem) Pipeline {
    this.Pipes = pipes

    return this
}

// 数组
func (this Pipeline) ThroughArray(pipes []PipeItem) Pipeline {
    this.Pipes = pipes

    return this
}

// 添加管道
func (this Pipeline) Pipe(pipes ...PipeItem) Pipeline {
    this.Pipes = append(this.Pipes, pipes...)

    return this
}

// 添加管道
func (this Pipeline) PipeArray(pipes []PipeItem) Pipeline {
    this.Pipes = append(this.Pipes, pipes...)

    return this
}

// 设置自定义方法
func (this Pipeline) Via(method string) Pipeline {
    this.Method = method

    return this
}

// 返回
func (this Pipeline) Then(destination DestinationFunc) any {
    pipeline := ArrayReduce(
        ArrayReverse(this.Pipes),
        this.Carry(),
        this.PrepareDestination(destination),
    )

    newPipeline := pipeline.(NextFunc)

    return newPipeline(this.Passable)
}

// 返回数据
func (this Pipeline) ThenReturn() any {
    return this.Then(func(passable any) any {
        return passable
    })
}

// 包装
func (this Pipeline) PrepareDestination(destination DestinationFunc) NextFunc {
    return func(passable any) any {
        return destination(passable)
    }
}

// 格式化数据
func (this Pipeline) Carry() CarryFunc {
    return func(stack any, pipe any) any {
        newStack := stack.(NextFunc)

        return func(passable any) any {

            // 判断类型
            switch newPipe := pipe.(type) {
                // 回调方法
                case PipeFunc:
                    return newPipe(passable, newStack)

                // 结构体
                case PipeInterface:
                    carry := newPipe.Handle(passable, newStack)

                    return this.HandleCarry(carry)

                // 默认报错
                default:
                    // 执行自定义函数
                    if carry, ok := this.pipeCallMethod(pipe, this.Method, []any{passable, newStack}); ok {
                        return this.HandleCarry(carry)
                    }

                    return this.HandleException(passable, pipe, newStack)
            }

        }
    }
}

// 获取设置的管道
func (this Pipeline) GetPipes() []PipeItem {
    return this.Pipes
}

// 返回数据
func (this Pipeline) HandleCarry(carry any) any {
    if this.CarryCallback != nil {
        callback := this.CarryCallback

        return callback(carry)
    }

    return carry
}

// 报错信息
func (this Pipeline) HandleException(passable any, pipe any, stack NextFunc) any {
    if this.ExceptionCallback != nil {
        callback := this.ExceptionCallback

        return callback(passable, pipe, stack)
    }

    return stack(passable)
}

// 设置 Carry 回调函数
func (this Pipeline) WithCarryCallback(callback CarryCallbackFunc) Pipeline {
    this.CarryCallback = callback

    return this
}

// 设置 Exception 回调函数
func (this Pipeline) WithExceptionCallback(callback ExceptionCallbackFunc) Pipeline {
    this.ExceptionCallback = callback

    return this
}

// 执行自定义方法
func (this Pipeline) pipeCallMethod(pipe any, method string, params []any) (any, bool) {
    if method == "" {
        return nil, false
    }

    // 不是结构体时
    pipeKind := reflect.TypeOf(pipe).Kind()
    if pipeKind != reflect.Struct {
        return nil, false
    }

    pipeObject := reflect.ValueOf(pipe)

    // 获取到方法
    newPipe := pipeObject.MethodByName(method)
    if !newPipe.IsValid() {
        return nil, false
    }

    // 添加参数
    pipeParams := make([]reflect.Value, 0)

    if len(params) > 0 {
        for _, param := range params {
            pipeParams = append(pipeParams, reflect.ValueOf(param))
        }
    }

    // 执行并获取结果
    carrys := newPipe.Call(pipeParams)
    if len(carrys) == 0 {
        return nil, false
    }

    carry := carrys[0].Interface()

    return carry, true
}

