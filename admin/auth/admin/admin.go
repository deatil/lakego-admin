package admin

import (
    "lakego-admin/lakego/collection"
    "lakego-admin/lakego/facade/config"
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

    // 格式化分组
    adminGroups := admin.Data["Groups"].([]interface{})
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
    profile := make(map[string]interface{})

    profile["id"] = admin.Data["id"]
    profile["name"] = admin.Data["name"]
    profile["email"] = admin.Data["email"]
    profile["nickname"] = admin.Data["nickname"]
    profile["avatar"] = admin.Data["avatar"]
    profile["introduce"] = admin.Data["introduce"]
    profile["groups"] = admin.GetGroups()
    profile["last_login_time"] = admin.Data["last_login_time"]
    profile["last_login_ip"] = admin.Data["last_login_ip"]

    return profile
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
    // 格式化分组
    adminGroups := admin.Data["Groups"].([]interface{})
    ids := collection.
        Collect(adminGroups).
        Pluck("id").
        ToStringArray()

    return ids
}

