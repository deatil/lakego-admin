package passport

import (
    "github.com/deatil/lakego-doak/lakego/facade/validate"
)

// 账号信息更新
func Update(data map[string]any) string {
    // 规则
    rules := map[string]any{
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

// 更新头像
func UpdateAvatar(data map[string]any) string {
    // 规则
    rules := map[string]any{
        "avatar": "required,len=36",
    }

    // 错误提示
    messages := map[string]string{
        "avatar.required": "头像数据不能为空",
        "avatar.len": "头像数据错误",
    }

    _, errs := validate.ValidateMap(data, rules, messages)

    if len(errs) > 0 {
        for _, err := range errs {
            return err
        }
    }

    return ""
}

// 修改密码
func UpdatePasssword(data map[string]any) string {
    // 规则
    rules := map[string]any{
        "oldpassword": "required,len=32",
        "newpassword": "required,len=32",
        "newpassword_confirm": "required,len=32",
    }

    // 错误提示
    messages := map[string]string{
        "oldpassword.required": "旧密码不能为空",
        "oldpassword.len": "旧密码错误",
        "newpassword.required": "新密码不能为空",
        "newpassword.len": "新密码错误",
        "newpassword_confirm.required": "确认密码不能为空",
        "newpassword_confirm.len": "确认密码错误",
    }

    _, errs := validate.ValidateMap(data, rules, messages)

    if len(errs) > 0 {
        for _, err := range errs {
            return err
        }
    }

    return ""
}
