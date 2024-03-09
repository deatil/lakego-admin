package validate

import (
    "fmt"
    "strings"

    "github.com/go-playground/locales/zh"
    "github.com/go-playground/validator/v10"
    ut "github.com/go-playground/universal-translator"
    zh_trans "github.com/go-playground/validator/v10/translations/zh"
)

var (
    // 默认翻译
    defaultTrans = "zh"

    // 默认
    defaultValidate *validate

    // 所有验证器
    validations []Validation
)

/**
 * 注册自定义验证器
 */
func init() {
    // 注册自定义验证器
    registerValidations()

    defaultValidate, _ = New()
}

// 设置默认翻译
func SetTrans(trans string) {
    defaultTrans = trans
}

// 添加验证器
func AddValidations(v ...Validation) {
    validations = append(validations, v...)
}

// 错误信息
type Errors struct {
    errs map[string]string
}

// NewErrors
func NewErrors(errs map[string]string) Errors {
    return Errors{
        errs: errs,
    }
}

// 错误数量
func (this Errors) Len() int {
    return len(this.errs)
}

// 返回第一个
func (this Errors) First() string {
    if len(this.errs) > 0 {
        for _, err := range this.errs {
            return err
        }
    }

    return ""
}

// 获取单独错误
func (this Errors) Data(name string) string {
    return this.errs[name]
}

// 返回全部
func (this Errors) All() map[string]string {
    return this.errs
}

/**
 * 自定义验证器
 *
 * @create 2021-9-6
 * @author deatil
 */
type validate struct {
    validate *validator.Validate
    trans    ut.Translator
}

// 初始化一个验证器
func New() (cv *validate, err error) {
    v := validator.New()
    local := zh.New()
    uniTrans := ut.New(local, local)

    translator, _ := uniTrans.GetTranslator(defaultTrans)

    // 批量注册参数验证表达式
    for i := range validations {
        validation := validations[i]
        err = validation.Register(v, translator)
        if err != nil {
            return
        }
    }

    // RegisterTranslation chinese as default translators for validate.
    err = zh_trans.RegisterDefaultTranslations(v, translator)
    if err != nil {
        return
    }

    cv = &validate{
        validate: v,
        trans:    translator,
    }

    return
}

// 获取验证器
func (this *validate) GetValidate() *validator.Validate {
    return this.validate
}

// 获取翻译
func (this *validate) GetTranslator() ut.Translator {
    return this.trans
}

// 字段验证
func (this *validate) Validate(
    data    any,
    message map[string]string,
) (bool, Errors) {
    result := make(map[string]string)

    err := this.validate.Struct(data)
    if err != nil {
        for _, e := range err.(validator.ValidationErrors) {
            namespace := e.Namespace()
            field     := e.Field()
            structNamespace := e.StructNamespace()
            structField     := e.StructField()
            tag       := e.Tag()
            actualTag := e.ActualTag()
            kind   := e.Kind().String()
            value  := fmt.Sprintf("%s", e.Value())
            param  := e.Param()
            errstr := e.(error).Error()

            typer := ""
            if e.Type() != nil {
                typer = e.Type().String()
            } else {
                typer = ""
            }

            if str, ok := message[field + "." + tag]; ok {
                str = strings.Replace(str, ":namespace", namespace, -1)
                str = strings.Replace(str, ":field", field, -1)
                str = strings.Replace(str, ":structNamespace", structNamespace, -1)
                str = strings.Replace(str, ":structField", structField, -1)
                str = strings.Replace(str, ":tag", tag, -1)
                str = strings.Replace(str, ":actualTag", actualTag, -1)
                str = strings.Replace(str, ":kind", kind, -1)
                str = strings.Replace(str, ":value", value, -1)
                str = strings.Replace(str, ":param", param, -1)
                str = strings.Replace(str, ":error", errstr, -1)
                str = strings.Replace(str, ":type", typer, -1)

                result[field + "." + tag] = str
            } else {
                result[field + "." + tag] = e.Translate(this.trans)
            }
        }

        return false, NewErrors(result)
    }

    return true, NewErrors(result)
}

// 验证器
// 返回验证器验证结果错误消息 和 bool (是否验证成功)
func Validate(
    data    any,
    message map[string]string,
) (bool, Errors) {
    return defaultValidate.Validate(data, message)
}

// 字段验证
// 使用验证器验证字段
// 当有错误时，此只返回单个错误描述
func (this *validate) ValidateError(
    data    any,
    message map[string]string,
) (bool, string) {
    ok, errs := this.Validate(data, message)

    return ok, errs.First()
}

// 验证器
// 返回验证器验证结果错误消息 和 bool (是否验证成功)
func ValidateError(
    data    any,
    message map[string]string,
) (bool, string) {
    return defaultValidate.ValidateError(data, message)
}

// map 验证
func (this *validate) ValidateMap(
    data    map[string]any,
    rules   map[string]any,
    message map[string]string,
) (bool, Errors) {
    result := make(map[string]string)

    // 检测结果
    errs := this.validate.ValidateMap(data, rules)
    if len(errs) > 0 {
        // 字段，错误
        for field, err := range errs {
            // 每个字段结果
            if err != nil {
                for _, e := range err.(validator.ValidationErrors) {
                    tag       := e.Tag()
                    value     := fmt.Sprintf("%s", e.Value())
                    namespace := e.Namespace()
                    errstr    := e.(error).Error()

                    typer := ""
                    if e.Type() != nil {
                        typer = e.Type().String()
                    } else {
                        typer = ""
                    }

                    if str, ok := message[field + "." + tag]; ok {
                        str = strings.Replace(str, ":field", field, -1)
                        str = strings.Replace(str, ":value", value, -1)
                        str = strings.Replace(str, ":tag", tag, -1)
                        str = strings.Replace(str, ":namespace", namespace, -1)
                        str = strings.Replace(str, ":error", errstr, -1)
                        str = strings.Replace(str, ":type", typer, -1)

                        result[field + "." + tag] = str
                    } else {
                        result[field + "." + tag] = e.Translate(this.trans)
                    }
                }
            }

        }

        return false, NewErrors(result)
    }

    return true, NewErrors(result)
}

// map 验证器
func ValidateMap(
    data    map[string]any,
    rules   map[string]any,
    message map[string]string,
) (bool, Errors) {
    return defaultValidate.ValidateMap(data, rules, message)
}

// map 验证，只返回一个错误值
// 使用验证器验证字段
// 当有错误时，此只返回单个错误描述
func (this *validate) ValidateMapError(
    data    map[string]any,
    rules   map[string]any,
    message map[string]string,
) (bool, string) {
    ok, errs := this.ValidateMap(data, rules, message)

    return ok, errs.First()
}

// map 验证器
func ValidateMapError(
    data    map[string]any,
    rules   map[string]any,
    message map[string]string,
) (bool, string) {
    return defaultValidate.ValidateMapError(data, rules, message)
}

// 单独判断
func (this *validate) Var(data string, rule string) (bool, error) {
    err := this.validate.Var(data, rule)
    if err != nil {
        return false, err
    }

    return true, nil
}

// Var 验证器
func Var(data string, rule string) (bool, error) {
    return defaultValidate.Var(data, rule)
}

// 注册自定义验证器
/*
Example:

validation := Validation{
    Tag:         "great_then",
    Translation: "字段 {0} 必须大于 {1}.",
    Override:    false,
    RegisterFn: func(ut ut.Translator) error {
        return ut.Add("great_then", "字段 {0} 必须大于 {1}.", false)
    },
    ValidateFn: func(fl validator.FieldLevel) bool {
        p, _ := strconv.Atoi(fl.Param())
        return fl.Field().Int() > int64(p)
    },
    TranslationFn: func(ut ut.Translator, fe validator.FieldError) string {
        t, err := ut.T(fe.Tag(), fe.Field(), fe.Param())
        if err != nil {
            t = "翻译失败"
        }
        return t
    },
},
*/
func registerValidations() {
    validations = append(validations,
        // 国内手机号码
        ValidationOfRegexp("phone", "^1[0-9]{10}$", "{0} 必须是手机号码"),

        // 常规用户名
        ValidationOfRegexp("username", "^[a-zA-Z][a-zA-Z0-9_]{4,15}$", "{0} 必须只包含大小写字母, 数字, 下划线, 且长度为 4-15"),

        // 标准域名
        ValidationOfRegexp("domain", "[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(/.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+/.?", "{0} 必须是标准域名"),

        // 强密码
        ValidationOfRegexp("strong_password", "^[a-zA-Z][a-zA-Z0-9_]{8,}$", "{0} 必须包含写字母和数字, 且长度为 8-16"),

        // 中国邮政编码
        ValidationOfRegexp("cn_postal_code", `[0-8][0-7]\d{4}`, "{0} 必须是中国邮政编码"),

        // 中国大陆身份证号
        ValidationOfRegexp("cn_id_number", `^\d{15}|\d{18}$`, "{0} 必须是中国身份证号码"),
    )
}
