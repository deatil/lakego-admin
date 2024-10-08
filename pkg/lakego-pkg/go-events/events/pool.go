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
type Pool struct{}

func NewPool() *Pool {
	return &Pool{}
}

// Call Func
func (this *Pool) Call(fn any, args []any) any {
	switch in := fn.(type) {
	case []any:
		if len(in) > 1 {
			method := ""
			if methodName, ok := in[1].(string); ok {
				method = methodName
			}

			return this.call(in[0], method, args)
		} else if len(in) == 1 {
			return this.call(in[0], "", args)
		}

		panic("go-events: call slice func error")
	default:
		return this.call(in, "", args)
	}
}

func (this *Pool) call(in any, method string, params []any) any {
	if eventMethod, ok := in.(reflect.Value); ok {
		if eventMethod.Kind() == reflect.Func {
			return this.CallFunc(eventMethod, params)
		}

		return this.CallStructMethod(eventMethod, method, params)
	} else if this.IsFunc(in) {
		return this.CallFunc(in, params)
	} else {
		return this.CallStructMethod(in, method, params)
	}
}

// Call Func
func (this *Pool) CallFunc(fn any, args []any) any {
	var val reflect.Value
	if fnVal, ok := fn.(reflect.Value); ok {
		val = fnVal
	} else {
		val = reflect.ValueOf(fn)
	}

	if val.Kind() != reflect.Func {
		panic("go-events: func type error")
	}

	return this.baseCall(val, args)
}

// Call struct method
func (this *Pool) CallStructMethod(class any, method string, args []any) any {
	var val reflect.Value
	if fnVal, ok := class.(reflect.Value); ok {
		val = fnVal
	} else {
		val = reflect.ValueOf(class)
	}

	if val.Kind() != reflect.Pointer && val.Kind() != reflect.Struct {
		panic("go-events: struct type error")
	}

	newMethod := val.MethodByName(method)
	return this.baseCall(newMethod, args)
}

// is Struct
func (this *Pool) IsStruct(in any) bool {
	val := reflect.ValueOf(in)
	if val.Kind() == reflect.Pointer || val.Kind() == reflect.Struct {
		return true
	}

	return false
}

// is Func
func (this *Pool) IsFunc(in any) bool {
	val := reflect.ValueOf(in)
	if val.Kind() == reflect.Func {
		return true
	}

	return false
}

// base Call Func
func (this *Pool) baseCall(fn reflect.Value, args []any) any {
	if fn.Kind() != reflect.Func {
		panic("go-events: call func type error")
	}

	if !fn.IsValid() {
		panic("go-events: call func valid error")
	}

	fnType := fn.Type()

	// 参数
	params := this.bindParams(fnType, args)

	res := fn.Call(params)
	if len(res) == 0 {
		return nil
	}

	return res[0].Interface()
}

// bind params
func (this *Pool) bindParams(fnType reflect.Type, args []any) []reflect.Value {
	numIn := fnType.NumIn()
	if len(args) != numIn {
		err := fmt.Sprintf("go-events: func params error (args %d, func args %d)", len(args), numIn)
		panic(err)
	}

	// 参数
	params := make([]reflect.Value, 0)
	for i := 0; i < numIn; i++ {
		dataValue := this.convertTo(fnType.In(i), args[i])
		params = append(params, dataValue)
	}

	return params
}

// src convert type to new typ
func (this *Pool) convertTo(typ reflect.Type, src any) reflect.Value {
	dataKey := getTypeName(typ)

	fieldType := reflect.TypeOf(src)
	if !fieldType.ConvertibleTo(typ) {
		return reflect.New(typ).Elem()
	}

	fieldValue := reflect.ValueOf(src)

	if dataKey != getTypeName(fieldType) {
		fieldValue = fieldValue.Convert(typ)
	}

	return fieldValue
}
