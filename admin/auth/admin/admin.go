package admin

import (
    "github.com/deatil/lakego-admin/lakego/collection"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/facade/permission"

    adminRepository "lakego-admin/admin/repository/admin"
    authruleRepository "lakego-admin/admin/repository/authrule"
    authgroupRepository "lakego-admin/admin/repository/authgroup"
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

func (admin *Admin) WithAccessToken(accessToken string) *Admin {
    admin.AccessToken = accessToken
    return admin
}

func (admin *Admin) GetAccessToken() string {
    return admin.AccessToken
}

func (admin *Admin) WithId(id string) *Admin {
    admin.Id = id
    return admin
}

func (admin *Admin) GetId() string {
    return admin.Id
}

func (admin *Admin) WithData(data map[string]interface{}) *Admin {
    admin.Data = data
    return admin
}

func (admin *Admin) GetData() map[string]interface{} {
    return admin.Data
}

// 是否为超级管理员
func (admin *Admin) IsSuperAdministrator() bool {
    if len(admin.Data) == 0 {
        return false
    }

    isRoot, ok := admin.Data["is_root"]

    if !ok {
        return false
    }

    if int(isRoot.(float64)) != 1 {
        return false
    }

    adminId := config.New("auth").GetString("Auth.AdminId")

    return admin.Id == adminId
}

// 是否激活
func (admin *Admin) IsActive() bool {
    if admin.IsSuperAdministrator() {
        return true
    }

    status := admin.Data["status"]
    return int(status.(float64)) == 1
}

// 所属分组是否激活
func (admin *Admin) IsGroupActive() bool {
    if admin.IsSuperAdministrator() {
        return true
    }

    adminGroups := admin.Data["Groups"].([]interface{})
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
func (admin *Admin) GetProfile() map[string]interface{} {
    profile := collection.Collect(admin.Data).
        Only([]string{
            "id", "name", "nickname",
            "email", "avatar", "introduce",
            "last_active", "last_ip",
        }).
        ToMap()

    profile["groups"] = admin.GetGroups()

    return profile
}

// 判断是否有权限
func (admin *Admin) HasAccess(slug string, method string) bool {
    if admin.IsSuperAdministrator() {
        return true
    }

    can, _ := permission.New().Enforce(admin.Id, slug, method)
    if can {
        return true
    }

    return false
}

// 当前账号所属分组
func (admin *Admin) GetGroups() []map[string]interface{} {
    groups := make([]map[string]interface{}, 0)

    // 格式化分组
    adminGroups := admin.Data["Groups"].([]interface{})

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
func (admin *Admin) GetGroupIds() []string {
    adminGroups := admin.Data["Groups"].([]interface{})

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
func (admin *Admin) GetGroupChildren() []map[string]interface{} {
    list := make([]map[string]interface{}, 0)

    groupids := admin.GetGroupIds()
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
func (admin *Admin) GetGroupChildrenIds() []string {
    list := admin.GetGroupChildren()
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
func (admin *Admin) GetRules() []map[string]interface{} {
    if admin.IsSuperAdministrator() {
        return authruleRepository.GetAllRule()
    }

    list := make([]map[string]interface{}, 0)

    groupids := admin.GetGroupIds()
    if len(groupids) == 0 {
        return list
    }

    return adminRepository.GetRules(groupids)
}

// 获取 ruleids
func (admin *Admin) GetRuleids() []string {
    list := admin.GetRules()

    if len(list) == 0 {
        return []string{}
    }

    return collection.
        Collect(list).
        Pluck("id").
        ToStringArray()
}

// 获取 slugs
func (admin *Admin) GetRuleSlugs() []string {
    list := admin.GetRules()

    if len(list) == 0 {
        return []string{}
    }

    return collection.
        Collect(list).
        Pluck("slug").
        ToStringArray()
}

