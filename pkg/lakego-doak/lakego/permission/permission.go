package permission

import (
    "github.com/casbin/casbin/v2"

    "github.com/deatil/lakego-doak/lakego/permission/interfaces"
)

// 构造函数
func New(adapter interfaces.Adapter, modelConf string) *Permission {
    perm := &Permission{}

    perm.WithModelConf(modelConf)
    perm.WithAdapter(adapter)

    perm.GetEnforcer()

    return perm
}

/**
 * 权限
 *
 * rbac_model.conf 中 matchers 内置可用函数：
 *   keyMatch [匹配*号], keyMatch2 [匹配 :file]
 *   regexMatch [正则匹配], ipMatch [IP地址或者CIDR匹配]
 *
 * @create 2021-9-30
 * @author deatil
 */
type Permission struct {
    // 权限文件
    ModelConf string

    // 适配器
    Adapter interfaces.Adapter

    // 决策器
    Enforcer *casbin.Enforcer
}

/**
 * 设置权限文件
 */
func (this *Permission) WithModelConf(modelConf string) *Permission {
    this.ModelConf = modelConf

    return this
}

/**
 * 获取权限文件
 */
func (this *Permission) GetModelConf() string {
    return this.ModelConf
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
    if this.Enforcer == nil {
        e, _ := casbin.NewEnforcer(this.ModelConf, this.Adapter)

        // Load the policy from DB.
        // e.LoadPolicy()

        // Save the policy back to DB.
        // e.SavePolicy()

        this.Enforcer = e
    }

    return this.Enforcer
}

/**
 * 添加用户角色
 */
func (this *Permission) AddRoleForUser(user string, role string) (bool, error) {
    return this.GetEnforcer().AddRoleForUser(user, role)
}

/**
 * 用户角色是否拥有某角色
 */
func (this *Permission) HasRoleForUser(user string, role string) (bool, error) {
    return this.GetEnforcer().HasRoleForUser(user, role)
}

/**
 * 删除用户角色
 */
func (this *Permission) DeleteRoleForUser(user string, role string) (bool, error) {
    return this.GetEnforcer().DeleteRoleForUser(user, role)
}

/**
 * 删除用户所有角色
 */
func (this *Permission) DeleteRolesForUser(user string) (bool, error) {
    return this.GetEnforcer().DeleteRolesForUser(user)
}

/**
 * 删除用户信息
 */
func (this *Permission) DeleteUser(user string) (bool, error) {
    return this.GetEnforcer().DeleteUser(user)
}

/**
 * 添加权限
 */
func (this *Permission) AddPolicy(user string, ptype string, rule string) (bool, error) {
    return this.GetEnforcer().AddPolicy(user, ptype, rule)
}

/**
 * 删除权限
 */
func (this *Permission) DeletePolicy(user string, ptype string, rule string) (bool, error) {
    return this.GetEnforcer().DeletePermissionForUser(user, ptype, rule)
}

/**
 * 删除标识所有权限
 */
func (this *Permission) DeletePolicys(user string) (bool, error) {
    return this.GetEnforcer().DeletePermissionForUser(user)
}

/**
 * 判断是否有权限
 */
func (this *Permission) HasPermissionForUser(user string, ptype string, rule string) bool {
    return this.GetEnforcer().HasPermissionForUser(user, ptype, rule)
}

/**
 * 全部权限
 */
func (this *Permission) GetPermissionsForUser(user string) [][]string {
    return this.GetEnforcer().GetPermissionsForUser(user)
}

/**
 * 验证用户权限
 */
func (this *Permission) Enforce(user string, ptype string, rule string) (bool, error) {
    return this.GetEnforcer().Enforce(user, ptype, rule)
}
