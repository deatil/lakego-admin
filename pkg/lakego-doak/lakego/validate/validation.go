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
    tag string
    // 表示该标 Validate 的描述/解释
    translation string
    // 是否覆盖已存在的验证器
    override bool
    // 用于验证字段的函数
    validateFn validator.Func
    // 翻译注册函数
    registerFn validator.RegisterTranslationsFunc
    // 翻译函数
    translationFn validator.TranslationFunc
}

func (this Validation) registerCustom(v customValidator) error {
    return this.register(v.validate, v.trans)
}

// 注册关联验证器
func (this *Validation) register(v *validator.Validate, t ut.Translator) (err error) {

    if this.validateFn != nil {
        err = v.RegisterValidation(this.tag, this.validateFn)
    }
    if err == nil {
        err = this.registerTranslation(v, t)
    }
    return
}

// 以下方法支持
func (this *Validation) registerTranslation(v *validator.Validate, t ut.Translator) (err error) {

    if this.translationFn != nil && this.registerFn != nil {

        err = v.RegisterTranslation(this.tag, t, this.registerFn, this.translationFn)

    } else if this.translationFn != nil && this.registerFn == nil {

        err = v.RegisterTranslation(this.tag, t, registrationFunc(this.tag, this.translation, this.override), this.translationFn)

    } else if this.translationFn == nil && this.registerFn != nil {

        err = v.RegisterTranslation(this.tag, t, this.registerFn, translateFunc)

    } else {
        err = v.RegisterTranslation(this.tag, t, registrationFunc(this.tag, this.translation, this.override), translateFunc)
    }

    return
}

// 创建正则验证器
func validationOfRegexp(tag string, regex string, translation string) Validation {
    re, err := regexp.Compile(regex)
    if err != nil {
        log.Print("创建正则自定义验证器: " + tag + " " + regex + " " + err.Error())
    }

    // 闭包持有外部变量整个伴随自己的生命周期
    fn := func(fl validator.FieldLevel) bool {
        field := fl.Field().String()
        return re.MatchString(field)
    }

    return Validation {
        tag:         tag,
        translation: translation,
        validateFn:  fn,
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
