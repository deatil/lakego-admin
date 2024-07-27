package pipeline

import(
    "fmt"
    "reflect"
)

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

// 构造函数
func NewPipeline() *Pipeline {
    return &Pipeline{
        Pipes:  make([]PipeItem, 0),
        Method: "Handle",
    }
}

// 构造函数
func New() *Pipeline {
    return NewPipeline()
}

// 设置数据
func (this *Pipeline) Send(passable any) *Pipeline {
    this.Passable = passable

    return this
}

// 设置管道
func (this *Pipeline) Through(pipes ...PipeItem) *Pipeline {
    this.Pipes = pipes

    return this
}

// 数组
func (this *Pipeline) ThroughArray(pipes []PipeItem) *Pipeline {
    this.Pipes = pipes

    return this
}

// 添加管道
func (this *Pipeline) Pipe(pipes ...PipeItem) *Pipeline {
    this.Pipes = append(this.Pipes, pipes...)

    return this
}

// 添加管道
func (this *Pipeline) PipeArray(pipes []PipeItem) *Pipeline {
    this.Pipes = append(this.Pipes, pipes...)

    return this
}

// 设置自定义方法
func (this *Pipeline) Via(method string) *Pipeline {
    this.Method = method

    return this
}

// 返回
func (this *Pipeline) Then(destination DestinationFunc) any {
    pipeline := ArrayReduce(
        ArrayReverse(this.Pipes),
        this.carry(),
        this.prepareDestination(destination),
    )

    newPipeline := pipeline.(NextFunc)

    return newPipeline(this.Passable)
}

// 返回数据
func (this *Pipeline) ThenReturn() any {
    return this.Then(func(passable any) any {
        return passable
    })
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

// 获取设置的管道
func (this *Pipeline) GetPipes() []PipeItem {
    return this.Pipes
}

// 包装
func (this *Pipeline) prepareDestination(destination DestinationFunc) NextFunc {
    return func(passable any) any {
        return destination(passable)
    }
}

// 格式化数据
func (this *Pipeline) carry() CarryFunc {
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

                    return this.handleCarry(carry)

                // slice
                case []any:
                    if len(newPipe) > 0 {
                        pipeFunc := newPipe[0]

                        params := []any{passable, newStack}
                        params = append(params, newPipe[1:]...)

                        // 执行自定义函数
                        if carry, ok := this.pipeCallMethod(pipeFunc, this.Method, params); ok {
                            return this.handleCarry(carry)
                        }
                    }

                    return this.handleException(passable, pipe, newStack)

                // 默认报错
                default:
                    // 执行自定义函数
                    if carry, ok := this.pipeCallMethod(pipe, this.Method, []any{passable, newStack}); ok {
                        return this.handleCarry(carry)
                    }

                    return this.handleException(passable, pipe, newStack)
            }

        }
    }
}

// 返回数据
func (this *Pipeline) handleCarry(carry any) any {
    if this.CarryCallback != nil {
        callback := this.CarryCallback

        return callback(carry)
    }

    return carry
}

// 报错信息
func (this *Pipeline) handleException(passable any, pipe any, stack NextFunc) any {
    if this.ExceptionCallback != nil {
        callback := this.ExceptionCallback

        return callback(passable, pipe, stack)
    }

    return stack(passable)
}

// 执行自定义方法
func (this *Pipeline) pipeCallMethod(pipe any, method string, params []any) (any, bool) {
    // 不是结构体时
    pipeType := reflect.TypeOf(pipe)
    for pipeType.Kind() == reflect.Ptr {
        pipeType = pipeType.Elem()
    }

    pipeKind := pipeType.Kind()
    switch {
        case pipeKind == reflect.Struct:
            if method == "" {
                return nil, false
            }

            // 获取到方法
            newPipe := reflect.ValueOf(pipe).MethodByName(method)

            // 执行并获取结果
            carry, ok := this.call(newPipe, params)
            if !ok {
                return nil, false
            }

            return carry, true
        case pipeKind == reflect.Func:
            newPipe := reflect.ValueOf(pipe)

            // 执行并获取结果
            carry, ok := this.call(newPipe, params)
            if !ok {
                return nil, false
            }

            return carry, true
    }

    return nil, false
}

// Call Func
func (this *Pipeline) call(fn reflect.Value, args []any) (any, bool) {
    if !fn.IsValid() {
        panic("go-pipeline: call func type error")
    }

    fnType := fn.Type()

    numIn := fnType.NumIn()
    if len(args) != numIn {
        err := fmt.Sprintf("go-pipeline: func params error (args %d, func args %d)", len(args), numIn)
        panic(err)
    }

    // 参数
    params := make([]reflect.Value, 0)
    for i := 0; i < numIn; i++ {
        dataValue := convertTo(fnType.In(i), args[i])
        params = append(params, dataValue)
    }

    res := fn.Call(params)
    if len(res) == 0 {
        return nil, false
    }

    return res[0].Interface(), true
}
