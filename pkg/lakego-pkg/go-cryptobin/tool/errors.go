package tool

// 构造函数
func NewErrors(errs []error) Errors {
    e := Errors{
        errors: make([]error, 0),
    }

    return e.Append(errs...)
}

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
func (this Errors) WithErrors(errs []error) Errors {
    return this.Reset().Append(errs...)
}

// 添加
func (this Errors) Append(errs ...error) Errors {
    for _, err := range errs {
        if err != nil {
            this.errors = append(this.errors, err)
        }
    }

    return this
}

// 前置添加
func (this Errors) Prepend(errs ...error) Errors {
    errors := make([]error, 0)

    for _, err := range errs {
        if err != nil {
            errors = append(errors, err)
        }
    }

    this.errors = append(errors, this.errors...)

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

// 实现 error 接口
func (this Errors) Error() string {
    var b []byte

    for i, err := range this.errors {
        if i > 0 {
            b = append(b, '\n')
        }

        b = append(b, err.Error()...)
    }

    return string(b)
}

// 返回全部错误字符
func (this Errors) String() string {
    return this.Error()
}

func (this Errors) Unwrap() []error {
    return this.errors
}

// 清空
func (this Errors) Reset() Errors {
    this.errors = make([]error, 0)

    return this
}
