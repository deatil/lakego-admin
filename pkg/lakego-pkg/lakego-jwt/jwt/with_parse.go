package jwt

// 自定义解析方式
func (this *JWT) WithParseFunc(name string, f func(*JWT) (interface{}, error)) *JWT {
    if _, ok := this.ParseFuncs[name]; ok {
        delete(this.ParseFuncs, name)
    }

    this.ParseFuncs[name] = f

    return this
}

// 批量设置自定义解析方式
func (this *JWT) WithParseFuncMany(funcs ParseFuncMap) *JWT {
    if len(funcs) > 0 {
        for k, v := range funcs {
            this.WithParseFunc(k, v)
        }
    }

    return this
}

// 移除自定义解析方式
func (this *JWT) WithoutParseFunc(name string) bool {
    if _, ok := this.ParseFuncs[name]; ok {
        delete(this.ParseFuncs, name)

        return true
    }

    return false
}
