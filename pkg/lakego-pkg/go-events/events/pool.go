package events

import (
    "fmt"
    "reflect"
)

/**
 * Pool
 *
 * @create 2024-7-26
 * @author deatil
 */
type Pool struct {}

func NewPool() *Pool {
    return &Pool{}
}

// Call Func
func (this *Pool) CallFunc(fn any, args []any) any {
    fnObject := reflect.ValueOf(fn)
    if !(fnObject.IsValid() && fnObject.Kind() == reflect.Func) {
        panic("pool: func type error")
    }

    return this.Call(fnObject, args)
}

// listen struct
func (this *Pool) CallStructMethod(in any, method string, args []any) any {
    typ := reflect.TypeOf(in)

    if typ.Kind() != reflect.Pointer && typ.Kind() != reflect.Struct {
        panic("pool: struct type error")
    }

    newMethod, ok := typ.MethodByName(method)
    if !ok {
        panic("pool: method not exists")
    }

	args = append([]any{in}, args...)
    return this.Call(newMethod.Func, args)
}

// Call Func
func (this *Pool) Call(fn reflect.Value, args []any) any {
    fnType := fn.Type()

    numIn := fnType.NumIn()
    if len(args) != numIn {
        err := fmt.Sprintf("pool: func params error (args %d, func args %d)", len(args), numIn)
        panic(err)
    }

    // 参数
    params := make([]reflect.Value, 0)
    for i := 0; i < numIn; i++ {
        dataValue := this.convertTo(fnType.In(i), args[i])
        params = append(params, dataValue)
    }

    res := fn.Call(params)
    if len(res) == 0 {
        return nil
    }

    return res[0].Interface()
}

// is Struct
func (this *Pool) IsStruct(in any) bool {
    typ := reflect.ValueOf(in)
    if typ.Kind() != reflect.Pointer && typ.Kind() != reflect.Struct {
        return false
    }

    return true
}

// is Func
func (this *Pool) IsFunc(in any) bool {
    fnObject := reflect.ValueOf(in)
    if !(fnObject.IsValid() && fnObject.Kind() == reflect.Func) {
        return false
    }

    return true
}

// src convert type to new typ
func (this *Pool) convertTo(typ reflect.Type, src any) reflect.Value {
    dataKey := getTypeKey(typ)

    fieldType := reflect.TypeOf(src)
    if !fieldType.ConvertibleTo(typ) {
        return reflect.New(typ).Elem()
    }

    fieldValue := reflect.ValueOf(src)

    if dataKey != getTypeKey(fieldType) {
        fieldValue = fieldValue.Convert(typ)
    }

    return fieldValue
}
