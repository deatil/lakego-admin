package passport

import (
    "lakego-admin/lakego/facade/validate"
)

// 账号信息更新
func Update(data map[string]interface{}) string {
    // 规则
    rules := map[string]interface{}{
        "nickname": "required,max=150",
        "email": "required,email,max=100",
        "introduce": "required,max=500",
    }

    // 错误提示
    messages := map[string]string{
        "nickname.required": "昵称不能为空",
        "nickname.max": "昵称字数超过了限制",
        "email.required": "邮箱不能为空",
        "email.email": "邮箱格式错误",
        "email.max": "邮箱字数超过了限制",
        "introduce.required": "简介不能为空",
        "introduce.max": "简介字数超过了限制",
    }

    _, errs := validate.ValidateMap(data, rules, messages)

    if len(errs) > 0 {
        for _, err := range errs {
            return err
        }
    }

    return ""
}

