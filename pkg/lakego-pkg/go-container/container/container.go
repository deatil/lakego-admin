package container

import (
    "fmt"
    "errors"
    "reflect"
)

// Container Bind data
type ContainerBind struct {
    // bind func
    Concrete any

    // shared
    Shared bool
}

/**
 * Container
 *
 * @create 2024-8-26
 * @author deatil
 */
type Container struct {
    // bind
    bind           map[string]ContainerBind

    // instances
    instances      map[string]any

    // invokeCallback
    invokeCallback map[string][]any
}

// NewContainer creates and returns a new *Container.
func NewContainer() *Container {
    container := &Container{
        bind:           make(map[string]ContainerBind),
        instances:      make(map[string]any),
        invokeCallback: make(map[string][]any),
    }

    container.Singleton(container, func() *Container {
        return container
    })

    return container
}

// New creates and returns a new *Container.
func New() *Container {
    return NewContainer()
}

// Provide
func (this *Container) Provide(fn any) error {
    fnValue := reflect.ValueOf(fn)
    fnType := fnValue.Type()

    numOut := fnType.NumOut()
    if numOut == 0 {
        return errors.New("go-container: Provide set fail")
    }

    abstract := getTypeKey(fnType.Out(0))

    this.Singleton(abstract, fn)

    return nil
}

// Invoke for get dep struct
func (this *Container) Invoke(fn any) any {
    return this.Call(fn, nil)
}

// Get object from bind
func (this *Container) Get(abstracts any) any {
    abstract := this.getAbstractName(abstracts)

    if this.Has(abstract) {
        return this.Make(abstract, nil)
    }

    panic(fmt.Sprintf("go-container: bind not exists: %s", abstract))
}

// Bind object
func (this *Container) Bind(abstract any, concrete any) *Container {
    return this.BindWithShared(abstract, concrete, false)
}

// Singleton object
func (this *Container) Singleton(abstract any, concrete any) *Container {
    return this.BindWithShared(abstract, concrete, true)
}

// Bind object With Shared
func (this *Container) BindWithShared(abstracts any, concrete any, shared bool) *Container {
    if isStruct(concrete) {
        abstract := this.getAbstractName(abstracts)

        this.Instance(abstract, concrete)
    } else {
        abstract := this.GetAlias(abstracts)

        this.bind[abstract] = ContainerBind{
            Concrete: concrete,
            Shared:   shared,
        }
    }

    return this
}

// Instance
func (this *Container) Instance(abstracts any, instance any) *Container {
    abstract := this.GetAlias(abstracts)

    this.bind[abstract] = ContainerBind{
        Shared: true,
    }

    this.instances[abstract] = instance

    return this
}

// Resolving
func (this *Container) Resolving(abstracts string, callback any) {
    abstract := this.getAbstractName(abstracts)

    if abstract == "*" {
        if _, ok := this.invokeCallback["*"]; !ok {
            this.invokeCallback["*"] = make([]any, 0)
        }

        this.invokeCallback["*"] = append(this.invokeCallback["*"], callback)
    }

    abstract = this.GetAlias(abstract)

    if _, ok := this.invokeCallback[abstract]; !ok {
        this.invokeCallback[abstract] = make([]any, 0)
    }

    this.invokeCallback[abstract] = append(this.invokeCallback[abstract], callback)
}

// Get Alias
func (this *Container) GetAlias(abstracts any) string {
    abstract := this.getAbstractName(abstracts)

    if _, ok := this.bind[abstract]; ok {
        bind := this.bind[abstract]

        if concrete, ok := bind.Concrete.(string); ok {
            return this.GetAlias(concrete)
        }
    }

    return abstract
}

// Make
func (this *Container) Make(abstracts any, vars []any) any {
    abstract := this.GetAlias(abstracts)

    bind := this.bind[abstract]

    if instance, ok := this.instances[abstract]; ok && bind.Shared {
        return instance
    }

    object := this.Call(bind.Concrete, vars)

    if bind.Shared {
        this.instances[abstract] = object
    }

    this.invokeAfter(abstract, object)

    return object
}

// Bound
func (this *Container) Bound(abstracts any) bool {
    abstract := this.getAbstractName(abstracts)

    if _, ok := this.bind[abstract]; ok {
        return true
    }

    if _, ok := this.instances[abstract]; ok {
        return true
    }

    return false
}

// Has
func (this *Container) Has(abstracts any) bool {
    return this.Bound(abstracts)
}

// Exists
func (this *Container) Exists(abstracts any) bool {
    abstract := this.GetAlias(abstracts)

    if _, ok := this.instances[abstract]; ok {
        return true
    }

    return false
}

// IsShared
func (this *Container) IsShared(abstracts any) bool {
    abstract := this.getAbstractName(abstracts)

    if _, ok := this.instances[abstract]; ok {
        return true
    }

    if bind, ok := this.bind[abstract]; ok && bind.Shared {
        return true
    }

    return false
}

// Delete
func (this *Container) Delete(abstracts any) {
    abstract := this.GetAlias(abstracts)

    if _, ok := this.instances[abstract]; ok {
        delete(this.instances, abstract)
    }
}

// Delete
func (this *Container) invokeAfter(abstract string, object any) {
    if _, ok := this.invokeCallback["*"]; ok {
        for _, fn := range this.invokeCallback["*"] {
            this.Call(fn, []any{object, this})
        }
    }

    if _, ok := this.invokeCallback[abstract]; ok {
        for _, fn := range this.invokeCallback[abstract] {
            this.Call(fn, []any{object, this})
        }
    }
}

// Call
func (this *Container) Call(fn any, args []any) any {
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

            panic("go-container: call slice func error")
        default:
            return this.call(in, "", args)
    }
}

func (this *Container) call(fn any, method string, params []any) any {
    if eventMethod, ok := fn.(reflect.Value); ok {
        if eventMethod.Kind() == reflect.Func {
            return this.CallFunc(eventMethod, params)
        }

        return this.CallStructMethod(eventMethod, method, params)
    } else if isFunc(fn) {
        return this.CallFunc(fn, params)
    } else {
        return this.CallStructMethod(fn, method, params)
    }
}

// Call Func
func (this *Container) CallFunc(fn any, args []any) any {
    var val reflect.Value
    if fnVal, ok := fn.(reflect.Value); ok {
        val = fnVal
    } else {
        val = reflect.ValueOf(fn)
    }

    if val.Kind() != reflect.Func {
        panic("go-container: func type error")
    }

    return this.baseCall(val, args)
}

// Call struct method
func (this *Container) CallStructMethod(in any, method string, args []any) any {
    var val reflect.Value
    if fnVal, ok := in.(reflect.Value); ok {
        val = fnVal
    } else {
        val = reflect.ValueOf(in)
    }

    if val.Kind() != reflect.Pointer && val.Kind() != reflect.Struct {
        panic("go-container: struct type error")
    }

    newMethod := val.MethodByName(method)
    return this.baseCall(newMethod, args)
}

func (this *Container) getAbstractName(abstract any) string {
    if isStruct(abstract) {
        return getStructName(abstract)
    }

    if name, ok := abstract.(string); ok {
        return name
    }

    return ""
}

// base Call Func
func (this *Container) baseCall(fn reflect.Value, args []any) any {
    if fn.Kind() != reflect.Func {
        panic("go-container: call func type error")
    }

    if !fn.IsValid() {
        panic("go-container: call func valid error")
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
func (this *Container) bindParams(fnType reflect.Type, args []any) []reflect.Value {
    numIn := fnType.NumIn()

    newArgs := make([]any, 0)
    if len(args) == numIn {
        newArgs = args
    } else {
        j := 0
        for i := 0; i < numIn; i++ {
            fnTypeIn := fnType.In(i)
            fnTypeKind := fnTypeIn.Kind()
            fnTypeName := getTypeKey(fnTypeIn)

            if fnTypeKind == reflect.Pointer || fnTypeKind == reflect.Struct {
                if j < len(args) {
                    argsType := getStructName(args[j])

                    // 传入参数和函数参数类型一致时
                    if fnTypeName == argsType {
                        newArgs = append(newArgs, args[j])

                        j++
                    } else {
                        if this.Has(fnTypeName) {
                            newArgs = append(newArgs, this.Make(fnTypeName, nil))
                        }
                    }
                } else {
                    if this.Has(fnTypeName) {
                        newArgs = append(newArgs, this.Make(fnTypeName, nil))
                    }
                }

            } else if fnTypeKind == reflect.Interface {
                // when has set interface as key
                if this.Has(fnTypeName) {
                    newArgs = append(newArgs, this.Make(fnTypeName, nil))
                } else {
                    if name, ok := this.getImplementsBind(fnTypeIn); ok {
                        newArgs = append(newArgs, this.Make(name, nil))
                    }
                }
            } else {
                newArgs = append(newArgs, args[j])

                j++
            }
        }
    }

    if len(newArgs) != numIn {
        err := fmt.Sprintf("go-container: func params error (args %d, func args %d)", len(args), numIn)
        panic(err)
    }

    // 参数
    params := make([]reflect.Value, 0)
    for i := 0; i < numIn; i++ {
        dataValue := this.convertTo(fnType.In(i), newArgs[i])
        params = append(params, dataValue)
    }

    return params
}

// src convert type to new typ
func (this *Container) convertTo(typ reflect.Type, src any) reflect.Value {
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

func (this *Container) getImplementsBind(typ reflect.Type) (string, bool) {
    for name, bind := range this.bind {
        concreteType := reflect.ValueOf(bind.Concrete).Type()

        if concreteType.NumOut() > 0 {
            value := concreteType.Out(0)
            valueName := getTypeKey(value)

            if ifImplements(value, typ) && valueName == name {
                return name, true
            }
        }
    }

    return "", false
}

