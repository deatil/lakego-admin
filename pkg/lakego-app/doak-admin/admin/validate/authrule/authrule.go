package authrule

import (
    "github.com/deatil/lakego-doak/lakego/facade/validate"
)

// 创建验证
func Create(data map[string]any) string {
    // 规则
    rules := map[string]any{
        "parentid": "required",
        "title": "required,max=50",
        "url": "required,max=250",
        "method": "required,max=10",
        "slug": "required",
        "status": "required",
    }

    // 错误提示
    messages := map[string]string{
        "parentid.required": "父级分类不能为空",
        "title.required": "名称不能为空",
        "title.max": "名称最大字符需要50个",
        "url.required": "权限链接不能为空",
        "url.max": "权限链接最大字符需要250个",
        "method.required": "请求类型不能为空",
        "method.max": "请求类型最大字符需要10个",
        "slug.required": "链接标识不能为空",
        "status.required": "状态选项不能为空",
    }

    ok, err := validate.ValidateMapReturnOneError(data, rules, messages)
    if ok {
        return ""
    }

    return err
}

// 编辑验证
func Update(data map[string]any) string {
    // 规则
    rules := map[string]any{
        "parentid": "required",
        "title": "required,max=50",
        "url": "required,max=250",
        "method": "required,max=10",
        "slug": "required",
        "status": "required",
    }

    // 错误提示
    messages := map[string]string{
        "parentid.required": "父级分类不能为空",
        "title.required": "名称不能为空",
        "title.max": "名称最大字符需要50个",
        "url.required": "权限链接不能为空",
        "url.max": "权限链接最大字符需要250个",
        "method.required": "请求类型不能为空",
        "method.max": "请求类型最大字符需要10个",
        "slug.required": "链接标识不能为空",
        "status.required": "状态选项不能为空",
    }

    ok, err := validate.ValidateMapReturnOneError(data, rules, messages)
    if ok {
        return ""
    }

    return err
}

