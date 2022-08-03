package container

import(
    "errors"
    "reflect"
)

// 执行结构体方法
func CallMethod(in any, method string, params []any) ([]any, error) {
    if method == "" {
        return nil, errors.New("method is empty.")
    }

    // 不是结构体时
    kind := reflect.TypeOf(in).Kind()
    if kind != reflect.Struct {
        return nil, errors.New("in data is not struct.")
    }

    object := reflect.ValueOf(in)

    // 获取到方法
    newMethod := object.MethodByName(method)
    if !newMethod.IsValid() {
        return nil, errors.New("method is error.")
    }

    // 添加参数
    newParams := make([]reflect.Value, 0)

    if len(params) > 0 {
        for _, param := range params {
            newParams = append(newParams, reflect.ValueOf(param))
        }
    }

    // 执行并获取结果
    values := newMethod.Call(newParams)

    // 返回结果
    data := make([]any, 0)
    if len(values) > 0 {
        for _, value := range values {
            data = append(data, value.Interface())
        }
    }

    return data, nil
}

// 执行函数
func CallFunc(fn any, params []any) ([]any, error) {
    object := reflect.ValueOf(fn)
    if !object.IsValid() {
        return nil, errors.New("method is error.")
    }

    // 不是函数时
    if object.Kind() != reflect.Func {
        return nil, errors.New("fn data is not func.")
    }

    // 添加参数
    newParams := make([]reflect.Value, 0)

    if len(params) > 0 {
        for _, param := range params {
            newParams = append(newParams, reflect.ValueOf(param))
        }
    }

    // 执行并获取结果
    values := object.Call(newParams)

    // 返回结果
    data := make([]any, 0)
    if len(values) > 0 {
        for _, value := range values {
            data = append(data, value.Interface())
        }
    }

    return data, nil
}

