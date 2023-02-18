package tool

// 构造函数
func NewError(errs ...error) *Errors {
    n := 0
    for _, err := range errs {
        if err != nil {
            n++
        }
    }

    if n == 0 {
        return nil
    }

    e := &Errors{
        errs: make([]error, 0, n),
    }

    for _, err := range errs {
        if err != nil {
            e.errs = append(e.errs, err)
        }
    }

    return e
}

// 构造函数
func NewErrors(errs []error) *Errors {
    e := &Errors{
        errs: make([]error, 0),
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
    errs []error
}

// 设置
func (this *Errors) WithErrors(errs []error) *Errors {
    return this.Reset().Append(errs...)
}

// 添加
func (this *Errors) Append(errs ...error) *Errors {
    for _, err := range errs {
        if err != nil {
            this.errs = append(this.errs, err)
        }
    }

    return this
}

// 前置添加
func (this *Errors) Prepend(errs ...error) *Errors {
    errors := make([]error, 0)

    for _, err := range errs {
        if err != nil {
            errors = append(errors, err)
        }
    }

    this.errs = append(errors, this.errs...)

    return this
}

// 第一个
func (this *Errors) First() error {
    if (len(this.errs) > 0) {
        return this.errs[0]
    }

    return nil
}

// 最后一个
func (this *Errors) Last() error {
    num := len(this.errs)
    if (num > 0) {
        return this.errs[num-1]
    }

    return nil
}

// 获取其中一个
func (this *Errors) Get(n int) error {
    num := len(this.errs)
    if (num > 0 && n > 0 && num > n) {
        return this.errs[n]
    }

    return nil
}

// 获取全部
func (this *Errors) All() []error {
    return this.errs
}

// 总数
func (this *Errors) Count() int {
    return len(this.errs)
}

// 循环
func (this *Errors) Range(fn func(int, error)) {
    num := len(this.errs)
    if (num > 0) {
        for k, v := range this.errs {
            fn(k, v)
        }
    }
}

// 实现 error 接口
func (this *Errors) Error() string {
    var b []byte

    for i, err := range this.errs {
        if i > 0 {
            b = append(b, '\n')
        }

        b = append(b, err.Error()...)
    }

    return string(b)
}

// 返回全部错误字符
func (this *Errors) String() string {
    return this.Error()
}

func (this *Errors) Unwrap() []error {
    return this.errs
}

func (this *Errors) IsNil() bool {
    return len(this.errs) == 0
}

// 清空
func (this *Errors) Reset() *Errors {
    this.errs = make([]error, 0)

    return this
}
