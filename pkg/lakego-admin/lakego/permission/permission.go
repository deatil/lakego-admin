package permission

import (
    "github.com/casbin/casbin/v2"

    "github.com/deatil/lakego-admin/lakego/permission/interfaces"
)

/**
 * 权限
 *
 * rbac_model.conf 中 matchers 内置可用函数：
 * keyMatch [匹配*号], keyMatch2 [匹配 :file]
 * regexMatch [正则匹配], ipMatch [IP地址或者CIDR匹配]
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
func (this *Permission) WithAdapter(a interfaces.Adapter) *Permission {
    this.Adapter = a

    return this
}

/**
 * 获取适配器
 */
func (this *Permission) GetAdapter() interfaces.Adapter {
    return this.Adapter
}

/**
 * 设置权限文件
 */
func (this *Permission) WithModelConf(modelConf string) *Permission {
    e, _ := casbin.NewEnforcer(modelConf, this.Adapter)

    // Load the policy from DB.
    // e.LoadPolicy()

    // Save the policy back to DB.
    // e.SavePolicy()

    this.WithEnforcer(e)

    return this
}

/**
 * 设置
 */
func (this *Permission) WithEnforcer(e *casbin.Enforcer) *Permission {
    this.Enforcer = e

    return this
}

/**
 * 获取
 */
func (this *Permission) GetEnforcer() *casbin.Enforcer {
    return this.Enforcer
}

/**
 * 添加用户角色
 */
func (this *Permission) AddRoleForUser(user string, role string) (bool, error) {
    return this.Enforcer.AddRoleForUser(user, role)
}

/**
 * 用户角色是否拥有某角色
 */
func (this *Permission) HasRoleForUser(user string, role string) (bool, error) {
    return this.Enforcer.HasRoleForUser(user, role)
}

/**
 * 删除用户角色
 */
func (this *Permission) DeleteRoleForUser(user string, role string) (bool, error) {
    return this.Enforcer.DeleteRoleForUser(user, role)
}

/**
 * 删除用户所有角色
 */
func (this *Permission) DeleteRolesForUser(user string) (bool, error) {
    return this.Enforcer.DeleteRolesForUser(user)
}

/**
 * 删除用户信息
 */
func (this *Permission) DeleteUser(user string) (bool, error) {
    return this.Enforcer.DeleteUser(user)
}

/**
 * 添加权限
 */
func (this *Permission) AddPolicy(user string, ptype string, rule string) (bool, error) {
    return this.Enforcer.AddPolicy(user, ptype, rule)
}

/**
 * 删除权限
 */
func (this *Permission) DeletePolicy(user string, ptype string, rule string) (bool, error) {
    return this.Enforcer.DeletePermissionForUser(user, ptype, rule)
}

/**
 * 删除标识所有权限
 */
func (this *Permission) DeletePolicys(user string) (bool, error) {
    return this.Enforcer.DeletePermissionForUser(user)
}

/**
 * 判断是否有权限
 */
func (this *Permission) HasPermissionForUser(user string, ptype string, rule string) bool {
    return this.Enforcer.HasPermissionForUser(user, ptype, rule)
}

/**
 * 全部权限
 */
func (this *Permission) GetPermissionsForUser(user string) [][]string {
    return this.Enforcer.GetPermissionsForUser(user)
}

/**
 * 验证用户权限
 */
func (this *Permission) Enforce(user string, ptype string, rule string) (bool, error) {
    return this.Enforcer.Enforce(user, ptype, rule)
}
