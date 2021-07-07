package admin

import (
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

// 当前账号信息
func (admin *Admin) GetProfile() map[string]interface{} {
	profile := make(map[string]interface{})

	profile["id"] = admin.Data["id"]
	profile["name"] = admin.Data["name"]
	profile["email"] = admin.Data["email"]
	profile["nickname"] = admin.Data["nickname"]
	profile["avatar"] = admin.Data["avatar"]
	profile["introduce"] = admin.Data["introduce"]
	// profile["groups"] = admin.Data["groups"]
	profile["last_login_time"] = admin.Data["last_login_time"]
	profile["last_login_ip"] = admin.Data["last_login_ip"]

	return profile
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

	if isRoot.(int) != 1 {
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

	return admin.Data["status"] == 1
}

// 所属分组是否激活
func (admin *Admin) IsGroupActive() bool {
	if admin.IsSuperAdministrator() {
		return true
	}

	return admin.Data["status"] == 1
}
