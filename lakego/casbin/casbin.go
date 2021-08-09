package casbin

import (
    "github.com/casbin/casbin/v2"
    casbinAdapter "lakego-admin/lakego/casbin/adapter"
    "lakego-admin/lakego/facade/database"
    "lakego-admin/lakego/support/path"
)

type Casbin struct {
    Enforcer *casbin.Enforcer
}

/**
 * Casbin
 *
 * @create 2021-6-20
 * @author deatil
 */
func New(model interface{}) *Casbin {
    newDb := database.New()

    // 配置文件路径
    configPath := path.GetConfigPath()
    modelConf := configPath + "/rbac_model.conf"

    a, _ := casbinAdapter.NewAdapterByDB(newDb, model)
    e, _ := casbin.NewEnforcer(modelConf, a)

    // Load the policy from DB.
    // e.LoadPolicy()

    // Save the policy back to DB.
    // e.SavePolicy()

    c := &Casbin{
        Enforcer: e,
    }

    return c
}

/**
 * 添加用户角色
 */
func (c *Casbin) AddRoleForUser(user string, role string) (bool, error) {
    return c.Enforcer.AddRoleForUser(user, role)
}

/**
 * 用户角色是否拥有某角色
 */
func (c *Casbin) HasRoleForUser(user string, role string) (bool, error) {
    return c.Enforcer.HasRoleForUser(user, role)
}

/**
 * 删除用户角色
 */
func (c *Casbin) DeleteRoleForUser(user string, role string) (bool, error) {
    return c.Enforcer.DeleteRoleForUser(user, role)
}

/**
 * 删除用户所有角色
 */
func (c *Casbin) DeleteRolesForUser(user string) (bool, error) {
    return c.Enforcer.DeleteRolesForUser(user)
}

/**
 * 删除用户信息
 */
func (c *Casbin) DeleteUser(user string) (bool, error) {
    return c.Enforcer.DeleteUser(user)
}

/**
 * 添加权限
 */
func (c *Casbin) AddPolicy(user string, ptype string, rule string) (bool, error) {
    return c.Enforcer.AddPolicy(user, ptype, rule)
}

/**
 * 删除权限
 */
func (c *Casbin) DeletePolicy(user string, ptype string, rule string) (bool, error) {
    return c.Enforcer.DeletePermissionForUser(user, ptype, rule)
}

/**
 * 删除标识所有权限
 */
func (c *Casbin) DeletePolicys(user string) (bool, error) {
    return c.Enforcer.DeletePermissionForUser(user)
}

/**
 * 判断是否有权限
 */
func (c *Casbin) HasPermissionForUser(user string, ptype string, rule string) bool {
    return c.Enforcer.HasPermissionForUser(user, ptype, rule)
}

/**
 * 全部权限
 */
func (c *Casbin) GetPermissionsForUser(user string) [][]string {
    return c.Enforcer.GetPermissionsForUser(user)
}

/**
 * 验证用户权限
 */
func (c *Casbin) Enforce(user string, ptype string, rule string) (bool, error) {
    return c.Enforcer.Enforce(user, ptype, rule)
}
