package tool

/**
 * 错误记录
 *
 * @create 2022-8-10
 * @author deatil
 */
type Errors struct {
    // 错误列表
    errors []error
}

// 设置
func (this Errors) WithErrors(errors []error) Errors {
    this.errors = errors

    return this
}

// 添加
func (this Errors) Append(err ...error) Errors {
    this.errors = append(this.errors, err...)

    return this
}

// 前置添加
func (this Errors) Prepend(err ...error) Errors {
    newErrors := make([]error, 0)
    newErrors = append(newErrors, err...)

    this.errors = append(newErrors, this.errors...)

    return this
}

// 第一个
func (this Errors) First() error {
    if (len(this.errors) > 0) {
        return this.errors[0]
    }

    return nil
}

// 最后一个
func (this Errors) Last() error {
    num := len(this.errors)
    if (num > 0) {
        return this.errors[num-1]
    }

    return nil
}

// 获取其中一个
func (this Errors) Get(n int) error {
    num := len(this.errors)
    if (num > 0 && n > 0 && num > n) {
        return this.errors[n]
    }

    return nil
}

// 获取全部
func (this Errors) All() []error {
    return this.errors
}

// 总数
func (this Errors) Count() int {
    return len(this.errors)
}

// 循环
func (this Errors) Each(fn func(int, error)) {
    num := len(this.errors)
    if (num > 0) {
        for k, v := range this.errors {
            fn(k, v)
        }
    }
}

// 返回第一个错误字符
func (this Errors) Error() string {
    err := this.First()
    if err != nil {
        return err.Error()
    }

    return ""
}

// 返回第一个错误字符
func (this Errors) String() string {
    return this.Error()
}

// 清空
func (this Errors) Reset() Errors {
    this.errors = make([]error, 0)

    return this
}

// 构造函数
func NewErrors(errs []error) Errors {
    err := Errors{
        errors: errs,
    }

    return err
}
