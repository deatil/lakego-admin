package passport

import (
    "github.com/deatil/lakego-doak/lakego/validate"
)

/*
user := map[string]any{
    "name": "Arshiya Kiani",
    "password": "6b4ee75684079f24bb6331d6b4abbb57",
    "captcha": "wert",
}
Login(user)
*/
func Login(data map[string]any) string {
    // 规则
    rules := map[string]any{
        "name": "required",
        "password": "required,len=32",
        "captcha": "required,len=4",
    }

    // 错误提示
    messages := map[string]string{
        "name.required": "name 字段必填",
        "password.required": "password 字段必填",
        "password.len": "password 字段为32位长度",
        "captcha.required": "captcha 字段必填",
        "captcha.len": ":field 字段为4位长度",
    }

    ok, err := validate.ValidateMapError(data, rules, messages)
    if ok {
        return ""
    }

    return err
}

