package admin

import (
    "github.com/deatil/lakego-doak/lakego/collection"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/facade/permission"

    adminRepository "github.com/deatil/lakego-doak/admin/repository/admin"
    authruleRepository "github.com/deatil/lakego-doak/admin/repository/authrule"
    authgroupRepository "github.com/deatil/lakego-doak/admin/repository/authgroup"
)

// 管理员账号结构体
type Admin struct {
    Id          string
    Data        map[string]interface{}
    AccessToken string
}

func New() *Admin {
    return &Admin{}
}

func (this *Admin) WithAccessToken(accessToken string) *Admin {
    this.AccessToken = accessToken
    return this
}

func (this *Admin) GetAccessToken() string {
    return this.AccessToken
}

func (this *Admin) WithId(id string) *Admin {
    this.Id = id
    return this
}

func (this *Admin) GetId() string {
    return this.Id
}

func (this *Admin) WithData(data map[string]interface{}) *Admin {
    this.Data = data
    return this
}

func (this *Admin) GetData() map[string]interface{} {
    return this.Data
}

// 是否为超级管理员
func (this *Admin) IsSuperAdministrator() bool {
    if len(this.Data) == 0 {
        return false
    }

    isRoot, ok := this.Data["is_root"]

    if !ok {
        return false
    }

    if int(isRoot.(float64)) != 1 {
        return false
    }

    adminId := config.New("auth").GetString("Auth.AdminId")

    return this.Id == adminId
}

// 是否激活
func (this *Admin) IsActive() bool {
    if this.IsSuperAdministrator() {
        return true
    }

    status := this.Data["status"]
    return int(status.(float64)) == 1
}

// 所属分组是否激活
func (this *Admin) IsGroupActive() bool {
    if this.IsSuperAdministrator() {
        return true
    }

    adminGroups := this.Data["Groups"].([]interface{})
    if len(adminGroups) == 0 {
        return false
    }

    status := collection.
        Collect(adminGroups).
        Every(func(item, value interface{}) bool {
            value2 := value.(map[string]interface{})

            status := value2["status"]
            if int(status.(float64)) == 1 {
                return false
            }

            return true
        })

    return !status
}

// 当前账号信息
func (this *Admin) GetProfile() map[string]interface{} {
    profile := collection.Collect(this.Data).
        Only([]string{
            "id", "name", "nickname",
            "email", "avatar", "introduce",
            "last_active", "last_ip",
        }).
        ToMap()

    profile["groups"] = this.GetGroups()
    profile["is_sa"] = this.IsSuperAdministrator()

    return profile
}

// 判断是否有权限
func (this *Admin) HasAccess(slug string, method string) bool {
    if this.IsSuperAdministrator() {
        return true
    }

    can, _ := permission.New().Enforce(this.Id, slug, method)
    if can {
        return true
    }

    return false
}

// 当前账号所属分组
func (this *Admin) GetGroups() []map[string]interface{} {
    groups := make([]map[string]interface{}, 0)

    // 格式化分组
    adminGroups := this.Data["Groups"].([]interface{})

    groups = collection.
        Collect(adminGroups).
        Each(func(item, value interface{}) (interface{}, bool) {
            value2 := value.(map[string]interface{})
            group := map[string]interface{}{
                "id": value2["id"],
                "title": value2["title"],
                "description": value2["description"],
            };

            return group, true
        }).
        ToMapArray()

    return groups
}

// 当前账号所属分组
func (this *Admin) GetGroupIds() []string {
    adminGroups := this.Data["Groups"].([]interface{})

    if len(adminGroups) == 0 {
        return []string{}
    }

    ids := collection.
        Collect(adminGroups).
        Pluck("id").
        ToStringArray()

    return ids
}

// 获取 GroupChildren
func (this *Admin) GetGroupChildren() []map[string]interface{} {
    list := make([]map[string]interface{}, 0)

    groupids := this.GetGroupIds()
    if len(groupids) == 0 {
        return list
    }

    list = authgroupRepository.GetChildrenFromGroupids(groupids)

    list = collection.Collect(list).
        Select(
            "id",
            "parentid",
            "title",
            "description",
        ).
        ToMapArray()

    return list
}

// 获取 GroupChildrenIds
func (this *Admin) GetGroupChildrenIds() []string {
    list := this.GetGroupChildren()
    if len(list) == 0 {
        return []string{}
    }

    ids := collection.
        Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

// 获取 rules
func (this *Admin) GetRules() []map[string]interface{} {
    if this.IsSuperAdministrator() {
        return authruleRepository.GetAllRule()
    }

    list := make([]map[string]interface{}, 0)

    groupids := this.GetGroupIds()
    if len(groupids) == 0 {
        return list
    }

    return adminRepository.GetRules(groupids)
}

// 获取 ruleids
func (this *Admin) GetRuleids() []string {
    list := this.GetRules()

    if len(list) == 0 {
        return []string{}
    }

    return collection.
        Collect(list).
        Pluck("id").
        ToStringArray()
}

// 获取 slugs
func (this *Admin) GetRuleSlugs() []string {
    list := this.GetRules()

    if len(list) == 0 {
        return []string{}
    }

    return collection.
        Collect(list).
        Pluck("slug").
        ToStringArray()
}

