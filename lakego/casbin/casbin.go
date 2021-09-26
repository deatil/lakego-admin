package casbin

import (
    "github.com/casbin/casbin/v2"

    "lakego-admin/lakego/casbin/interfaces"
)

type Casbin struct {
    // 适配器
    Adapter interfaces.Adapter

    // 决策器
    Enforcer *casbin.Enforcer
}

/**
 * 设置适配器
 */
func (c *Casbin) WithAdapter(a interfaces.Adapter) *Casbin {
    c.Adapter = a

    return c
}

/**
 * 获取适配器
 */
func (c *Casbin) GetAdapter() interfaces.Adapter {
    return c.Adapter
}

/**
 * 设置权限文件
 */
func (c *Casbin) WithModelConf(modelConf string) *Casbin {
    e, _ := casbin.NewEnforcer(modelConf, c.Adapter)

    // Load the policy from DB.
    // e.LoadPolicy()

    // Save the policy back to DB.
    // e.SavePolicy()

    c.WithEnforcer(e)

    return c
}

/**
 * 设置
 */
func (c *Casbin) WithEnforcer(e *casbin.Enforcer) *Casbin {
    c.Enforcer = e

    return c
}

/**
 * 获取
 */
func (c *Casbin) GetEnforcer() *casbin.Enforcer {
    return c.Enforcer
}

/**
 * 清空数据
 */
func (c *Casbin) ClearData() bool {
    c.Adapter.ClearData()

    return true
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
