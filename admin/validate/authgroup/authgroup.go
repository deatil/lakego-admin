package authgroup

import (
    "github.com/deatil/lakego-admin/lakego/facade/validate"
)

// 创建验证
func Create(data map[string]interface{}) string {
    // 规则
    rules := map[string]interface{}{
        "parentid": "required",
        "title": "required,max=50",
        "status": "required",
    }

    // 错误提示
    messages := map[string]string{
        "parentid.required": "父级分类不能为空",
        "title.required": "名称不能为空",
        "title.max": "名称最大字符需要50个",
        "status.required": "状态选项不能为空",
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
        "parentid": "required",
        "title": "required,max=50",
        "status": "required",
    }

    // 错误提示
    messages := map[string]string{
        "parentid.required": "父级分类不能为空",
        "title.required": "名称不能为空",
        "title.max": "名称最大字符需要50个",
        "status.required": "状态选项不能为空",
    }

    ok, err := validate.ValidateMapReturnOneError(data, rules, messages)
    if ok {
        return ""
    }

    return err
}

