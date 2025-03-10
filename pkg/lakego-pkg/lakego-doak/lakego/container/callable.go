package container

import(
    "errors"
    "reflect"
)

/**
 * 调用容器
 *
 * @create 2022-8-3
 * @author deatil
 */
type Callable struct {
    in        int
    out       int
    value     reflect.Value
    arguments []reflect.Type
    returns   []reflect.Type
    Error     error
}

// 构造函数
func NewCallable(fn any) Callable {
    callable := Callable{}

    return callable.Parse(fn)
}

// 调用
func (this Callable) Call(in []reflect.Value) []reflect.Value {
    return this.value.Call(in)
}

// 调用方法
func (this Callable) FnCall(params []any) []any {
    // 添加参数
    newParams := make([]reflect.Value, 0)

    if len(params) > 0 {
        for _, param := range params {
            newParams = append(newParams, reflect.ValueOf(param))
        }
    }

    // 执行并获取结果
    values := this.value.Call(newParams)

    // 返回结果
    data := make([]any, 0)
    if len(values) > 0 {
        for _, value := range values {
            data = append(data, value.Interface())
        }
    }

    return data
}

// 传入参数
func (this Callable) Arguments() []reflect.Type {
    return this.arguments
}

// 返回数据
func (this Callable) Returns() []reflect.Type {
    return this.returns
}

// 输入数量
func (this Callable) InNum() int {
    return this.in
}

// 输出数量
func (this Callable) OutNum() int {
    return this.out
}

// 解析
func (this Callable) Parse(fn any) Callable {
    var (
        fnValue = reflect.ValueOf(fn)
        fnType  = reflect.TypeOf(fn)
    )

    if fnValue.Kind() != reflect.Func {
        this.Error = errors.New("fn is not func.")

        return this
    }

    var (
        arguments    = make([]reflect.Type, 0)
        returns      = make([]reflect.Type, 0)
        argumentsLen = fnType.NumIn()
        returnsLen   = fnType.NumOut()
    )

    for fnIndex := 0; fnIndex < argumentsLen; fnIndex++ {
        arguments = append(arguments, fnType.In(fnIndex))
    }

    for outIndex := 0; outIndex < returnsLen; outIndex++ {
        returns = append(returns, fnType.Out(outIndex))
    }

    this.in        = argumentsLen
    this.out       = returnsLen
    this.value     = fnValue
    this.arguments = arguments
    this.returns   = returns

    return this
}
