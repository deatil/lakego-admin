package permission

import (
    "github.com/casbin/casbin/v2"

    "github.com/deatil/lakego-admin/lakego/permission/interfaces"
)

/**
 * 权限
 *
 * @create 2021-9-30
 * @author deatil
 */
type Permission struct {
    // 适配器
    Adapter interfaces.Adapter

    // 决策器
    Enforcer *casbin.Enforcer
}

/**
 * 设置适配器
 */
func (perm *Permission) WithAdapter(a interfaces.Adapter) *Permission {
    perm.Adapter = a

    return perm
}

/**
 * 获取适配器
 */
func (perm *Permission) GetAdapter() interfaces.Adapter {
    return perm.Adapter
}

/**
 * 设置权限文件
 */
func (perm *Permission) WithModelConf(modelConf string) *Permission {
    e, _ := casbin.NewEnforcer(modelConf, perm.Adapter)

    // Load the policy from DB.
    // e.LoadPolicy()

    // Save the policy back to DB.
    // e.SavePolicy()

    perm.WithEnforcer(e)

    return perm
}

/**
 * 设置
 */
func (perm *Permission) WithEnforcer(e *casbin.Enforcer) *Permission {
    perm.Enforcer = e

    return perm
}

/**
 * 获取
 */
func (perm *Permission) GetEnforcer() *casbin.Enforcer {
    return perm.Enforcer
}

/**
 * 清空数据
 */
func (perm *Permission) ClearData() bool {
    perm.Adapter.ClearData()

    return true
}

/**
 * 添加用户角色
 */
func (perm *Permission) AddRoleForUser(user string, role string) (bool, error) {
    return perm.Enforcer.AddRoleForUser(user, role)
}

/**
 * 用户角色是否拥有某角色
 */
func (perm *Permission) HasRoleForUser(user string, role string) (bool, error) {
    return perm.Enforcer.HasRoleForUser(user, role)
}

/**
 * 删除用户角色
 */
func (perm *Permission) DeleteRoleForUser(user string, role string) (bool, error) {
    return perm.Enforcer.DeleteRoleForUser(user, role)
}

/**
 * 删除用户所有角色
 */
func (perm *Permission) DeleteRolesForUser(user string) (bool, error) {
    return perm.Enforcer.DeleteRolesForUser(user)
}

/**
 * 删除用户信息
 */
func (perm *Permission) DeleteUser(user string) (bool, error) {
    return perm.Enforcer.DeleteUser(user)
}

/**
 * 添加权限
 */
func (perm *Permission) AddPolicy(user string, ptype string, rule string) (bool, error) {
    return perm.Enforcer.AddPolicy(user, ptype, rule)
}

/**
 * 删除权限
 */
func (perm *Permission) DeletePolicy(user string, ptype string, rule string) (bool, error) {
    return perm.Enforcer.DeletePermissionForUser(user, ptype, rule)
}

/**
 * 删除标识所有权限
 */
func (perm *Permission) DeletePolicys(user string) (bool, error) {
    return perm.Enforcer.DeletePermissionForUser(user)
}

/**
 * 判断是否有权限
 */
func (perm *Permission) HasPermissionForUser(user string, ptype string, rule string) bool {
    return perm.Enforcer.HasPermissionForUser(user, ptype, rule)
}

/**
 * 全部权限
 */
func (perm *Permission) GetPermissionsForUser(user string) [][]string {
    return perm.Enforcer.GetPermissionsForUser(user)
}

/**
 * 验证用户权限
 */
func (perm *Permission) Enforce(user string, ptype string, rule string) (bool, error) {
    return perm.Enforcer.Enforce(user, ptype, rule)
}
