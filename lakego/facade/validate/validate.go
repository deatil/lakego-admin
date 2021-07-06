package validate

import (
	"lakego-admin/lakego/validate"
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
func Validate(s interface{}, message map[string]string) (bool, map[string]string) {
	return validate.CustomValidator.Verify(s, message)
}

/**
 * map 验证器
 *
 * @create 2021-6-20
 * @author deatil
 */
func ValidateMap(data map[string]interface{}, rules map[string]interface{}, message map[string]string) (bool, map[string]string) {
	return validate.CustomValidator.ValidateMap(data, rules, message)
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
