package extension

import (
    "strings"

    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-tree/tree"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/array"

    "github.com/deatil/lakego-doak-admin/admin/model"
)

// 规则
type Rule struct {}

// 初始化
func NewRule() *Rule {
    r := &Rule{}

    return r
}

// 创建
func (this *Rule) Create(data map[string]any, parentId string) bool {
    if len(data) == 0 {
        return false
    }

    lastOrder := 0

    var info model.AuthRule
    err := model.NewAuthRule().
        Order("listorder DESC").
        First(&info).
        Error
    if err == nil {
        lastOrder = info.Listorder
    }

    res := array.ArrayFrom(data)

    insertData := model.AuthRule{
        Parentid:    parentId,
        Title:       res.Value("title").ToString(),
        Url:         res.Value("url").ToString(),
        Method:      strings.ToUpper(res.Value("method").ToString()),
        Slug:        res.Value("slug").ToString(),
        Description: res.Value("description", "").ToString(),
        Listorder:   goch.ToInt(lastOrder),
        Status:      0,
        AddTime:     int(datebin.NowTime()),
        AddIp:       "0.0.0.0",
    }

    err2 := model.NewDB().
        Create(&insertData).
        Error
    if err2 == nil {
        children := res.Value("children").ToSlice()
        for _, child := range children {
            if r, ok := child.(map[string]any); ok {
                this.Create(r, insertData.ID)
            }
        }
    }

    return true
}

// 删除
func (this *Rule) Delete(slug string) bool {
    ids := this.GetAuthRuleIdsBySlug(slug)
    if len(ids) == 0 {
        return false
    }

    for _, id := range ids {
        model.NewAuthRule().
            Delete(&model.AuthRule{
                ID: id,
            })
    }

    return true
}

// 启用
func (this *Rule) Enable(slug string) bool {
    ids := this.GetAuthRuleIdsBySlug(slug)
    if len(ids) == 0 {
        return false
    }

    for _, id := range ids {
        model.NewAuthRule().
            Where("id = ?", id).
            Updates(map[string]any{
                "status": 1,
            })
    }

    return true
}

// 禁用
func (this *Rule) Disable(slug string) bool {
    ids := this.GetAuthRuleIdsBySlug(slug)
    if len(ids) == 0 {
        return false
    }

    for _, id := range ids {
        model.NewAuthRule().
            Where("id = ?", id).
            Updates(map[string]any{
                "status": 0,
            })
    }

    return true
}

// 导出指定slug的规则
func (this *Rule) Export(slug string) []map[string]any {
    ruleList := make([]map[string]any, 0)

    ids := this.GetAuthRuleIdsBySlug(slug)
    if len(ids) == 0 {
        return ruleList
    }

    var info model.AuthRule

    // 模型
    err := model.NewAuthRule().
        Where("slug = ?", slug).
        First(&info).
        Error
    if err == nil {
        rules := make([]map[string]any, 0)

        model.NewAuthRule().
            Where("id IN ?", ids).
            Order("listorder ASC").
            Find(&rules)

        ruleList = tree.New[string]().
            WithData(rules).
            Build(info.ID, "", 1)
    }

    return ruleList
}

// 根据slug获取规则IDS
func (this *Rule) GetAuthRuleIdsBySlug(slug string) []string {
    ids := make([]string, 0)

    rules := make([]map[string]any, 0)
    model.NewAuthRule().
        Where("slug = ?", slug).
        Find(&rules)

    ruleList := make([]map[string]any, 0)
    model.NewAuthRule().
        Order("listorder ASC").
        Select("id", "parentid", "slug").
        Find(&ruleList)

    for _, rule := range rules {
        ruleId := rule["id"].(string)

        ruleIds := tree.New[string]().
            WithData(ruleList).
            GetListChildIds(ruleId)

        ids = append(ids, ruleIds...)
        ids = append(ids, ruleId)
    }

    return ids
}
