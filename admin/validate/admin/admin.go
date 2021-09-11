package admin

import (
    "lakego-admin/lakego/facade/validate"
)

// 创建验证
func Create(data map[string]interface{}) string {
    // 规则
    rules := map[string]interface{}{
        "name": "required,min=2,max=20",
        "nickname": "required,min=2,max=150",
        "email": "required,email,min=5,max=100",
        "introduce": "required,max=500,
        "status": "required,oneof='0|1'",
    }

    // 错误提示
    messages := map[string]string{
        "name.required": "账号不能为空",
        "name.min": "账号最小字符需要2个",
        "name.max": "账号最大字符需要20个",
        "nickname.required": "昵称不能为空",
        "nickname.min": "昵称最小字符需要2个",
        "nickname.max": "昵称最大字符需要150个",
        "email.required": "邮箱不能为空",
        "email.email": "邮箱格式错误",
        "email.min": "邮箱最小字符需要5个",
        "email.max": "邮箱最大字符需要100个",
        "introduce.required": "简介不能为空",
        "introduce.max": "简介字数最大字符需要500个",
        "status.required": "状态选项不能为空",
        "status.oneof": "状态选项值错误",
    }

    ok, err := validate.ValidateMapReturnOneError(data, rules, messages)
    if ok {
        return ""
    }

    return err
}

// 编辑验证
func Update(data map[string]interface{}) string {
    // 规则
    rules := map[string]interface{}{
        "group_id": "required",
        "name": "required,min=2,max=20",
        "nickname": "required,min=2,max=150",
        "email": "required,email,min=5,max=100",
        "introduce": "required,max=500,
        "status": "required,oneof='0|1'",
    }

    // 错误提示
    messages := map[string]string{
        "group_id.required": "账号所属分组不能为空",
        "name.required": "账号不能为空",
        "name.min": "账号最小字符需要2个",
        "name.max": "账号最大字符需要20个",
        "nickname.required": "昵称不能为空",
        "nickname.min": "昵称最小字符需要2个",
        "nickname.max": "昵称最大字符需要150个",
        "email.required": "邮箱不能为空",
        "email.email": "邮箱格式错误",
        "email.min": "邮箱最小字符需要5个",
        "email.max": "邮箱最大字符需要100个",
        "introduce.required": "简介不能为空",
        "introduce.max": "简介字数最大字符需要500个",
        "status.required": "状态选项不能为空",
        "status.oneof": "状态选项值错误",
    }

    ok, err := validate.ValidateMapReturnOneError(data, rules, messages)
    if ok {
        return ""
    }

    return err
}

// 修改头像
func UpdateAvatar(data map[string]interface{}) string {
    // 规则
    rules := map[string]interface{}{
        "avatar": "required,len=32",
    }

    // 错误提示
    messages := map[string]string{
        "avatar.required": "头像数据不能为空",
        "avatar.len": "头像数据错误",
    }

    ok, err := validate.ValidateMapReturnOneError(data, rules, messages)
    if ok {
        return ""
    }

    return err
}

