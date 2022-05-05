package validate

import (
    "github.com/deatil/lakego-doak/lakego/validate"
)

/**
 * 添加验证器
 *
 * @create 2021-6-20
 * @author deatil
 */
func WithValidations(v validate.Validation) {
    validate.WithValidations(v)
}

/**
 * 验证器
 * 返回验证器验证结果错误消息 和 bool (是否验证成功)
 *
 * @create 2021-6-20
 * @author deatil
 */
func Validate(s any, message map[string]string) (bool, map[string]string) {
    return validate.CustomValidator.Verify(s, message)
}

/**
 * 验证器
 * 返回验证器验证结果错误消息 和 bool (是否验证成功)
 *
 * @create 2021-9-11
 * @author deatil
 */
func VerifyReturnOneError(s any, message map[string]string) (bool, string) {
    return validate.CustomValidator.VerifyReturnOneError(s, message)
}

/**
 * map 验证器
 *
 * @create 2021-6-20
 * @author deatil
 */
func ValidateMap(data map[string]any, rules map[string]any, message map[string]string) (bool, map[string]string) {
    return validate.CustomValidator.ValidateMap(data, rules, message)
}

/**
 * map 验证器
 *
 * @create 2021-9-11
 * @author deatil
 */
func ValidateMapReturnOneError(data map[string]any, rules map[string]any, message map[string]string) (bool, string) {
    return validate.CustomValidator.ValidateMapReturnOneError(data, rules, message)
}

/**
 * Var 验证器
 *
 * @create 2021-6-20
 * @author deatil
 */
func Var(data string, rule string) (bool, error) {
    return validate.CustomValidator.Var(data, rule)
}
