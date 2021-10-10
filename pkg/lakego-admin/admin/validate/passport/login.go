package passport

import (
    "github.com/deatil/lakego-admin/lakego/facade/validate"
)

/*
user := map[string]interface{}{
    "name": "Arshiya Kiani", 
    "password": "6b4ee75684079f24bb6331d6b4abbb57",
    "captcha": "wert",
}
Login(user)
*/
func Login(data map[string]interface{}) string {
    // 规则
    rules := map[string]interface{}{
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

    _, errs := validate.ValidateMap(data, rules, messages)

    if len(errs) > 0 {
        for _, err := range errs {
            return err
        }
    }
    
    return ""
}

