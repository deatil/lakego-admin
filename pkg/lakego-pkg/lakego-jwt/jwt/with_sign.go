package jwt

// 签名方式
func (this *JWT) WithSignMethod(name string, method SigningMethod) *JWT {
    if _, ok := this.SigningMethods[name]; ok {
        delete(this.SigningMethods, name)
    }

    this.SigningMethods[name] = method

    return this
}

// 批量设置签名方式
func (this *JWT) WithSignMethodMany(methods SigningMethodMap) *JWT {
    if len(methods) > 0 {
        for k, v := range methods {
            this.WithSignMethod(k, v)
        }
    }

    return this
}

// 移除签名方式
func (this *JWT) WithoutSignMethod(name string) bool {
    if _, ok := this.SigningMethods[name]; ok {
        delete(this.SigningMethods, name)
        return true
    }

    return false
}

// 自定义签名方式
func (this *JWT) WithSigningFunc(name string, f func(*JWT) (interface{}, error)) *JWT {
    if _, ok := this.SigningFuncs[name]; ok {
        delete(this.SigningFuncs, name)
    }

    this.SigningFuncs[name] = f

    return this
}

// 批量设置自定义签名方式
func (this *JWT) WithSigningFuncMany(funcs SigningFuncMap) *JWT {
    if len(funcs) > 0 {
        for k, v := range funcs {
            this.WithSigningFunc(k, v)
        }
    }

    return this
}

// 移除自定义签名方式
func (this *JWT) WithoutSigningFunc(name string) bool {
    if _, ok := this.SigningFuncs[name]; ok {
        delete(this.SigningFuncs, name)

        return true
    }

    return false
}
