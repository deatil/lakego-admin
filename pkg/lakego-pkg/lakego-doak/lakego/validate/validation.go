package validate

import (
    "log"
    "regexp"
    "github.com/go-playground/validator/v10"
    ut "github.com/go-playground/universal-translator"
)

// 表示 validator.Validate 和 ut.Translator 的组合.
// 包含验证标签, 方式, 翻译器等基本要素
// 其中, tag 为必要字段
//
// 当存在 translation 时, 其他均为可选, 表示重写一个 tag 的翻译器
type Validation struct {
    // 标签名称
    Tag           string
    // 表示该标 Validate 的描述/解释
    Translation   string
    // 是否覆盖已存在的验证器
    Override      bool
    // 用于验证字段的函数
    ValidateFn    validator.Func
    // 翻译注册函数
    RegisterFn    validator.RegisterTranslationsFunc
    // 翻译函数
    TranslationFn validator.TranslationFunc
}

func (this Validation) RegisterCustom(v validate) error {
    return this.Register(v.validate, v.trans)
}

// 注册关联验证器
func (this *Validation) Register(v *validator.Validate, t ut.Translator) (err error) {
    if this.ValidateFn != nil {
        err = v.RegisterValidation(this.Tag, this.ValidateFn)
    }

    if err == nil {
        err = this.RegisterTranslation(v, t)
    }

    return
}

// 以下方法支持
func (this *Validation) RegisterTranslation(v *validator.Validate, t ut.Translator) (err error) {
    switch {
        case this.TranslationFn != nil && this.RegisterFn != nil:
            err = v.RegisterTranslation(this.Tag, t, this.RegisterFn, this.TranslationFn)
        case this.TranslationFn != nil && this.RegisterFn == nil:
            err = v.RegisterTranslation(this.Tag, t, registrationFunc(this.Tag, this.Translation, this.Override), this.TranslationFn)
        case this.TranslationFn == nil && this.RegisterFn != nil:
            err = v.RegisterTranslation(this.Tag, t, this.RegisterFn, translateFunc)
        default:
            err = v.RegisterTranslation(this.Tag, t, registrationFunc(this.Tag, this.Translation, this.Override), translateFunc)
    }

    return
}

// 创建正则验证器
func ValidationOfRegexp(tag string, regex string, translation string) Validation {
    re, err := regexp.Compile(regex)
    if err != nil {
        log.Print("Create Validation: " + tag + " " + regex + " " + err.Error())
    }

    // 闭包持有外部变量整个伴随自己的生命周期
    fn := func(fl validator.FieldLevel) bool {
        field := fl.Field().String()
        return re.MatchString(field)
    }

    return Validation {
        Tag:         tag,
        Translation: translation,
        ValidateFn:  fn,
    }
}

func translateFunc(ut ut.Translator, fe validator.FieldError) string {
    t, err := ut.T(fe.Tag(), fe.Field())
    if err != nil {
        return fe.(error).Error()
    }

    return t
}

func registrationFunc(tag string, translation string, override bool) validator.RegisterTranslationsFunc {
    return func(ut ut.Translator) error {
        return ut.Add(tag, translation, override)
    }
}
