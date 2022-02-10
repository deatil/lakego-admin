package except

import (
    "sync"
)

/**
 * 权限过滤
 *
 * @create 2021-9-2
 * @author deatil
 */

// 单例
var once sync.Once

// 登陆过滤 ["GET:passport/login"]
var authenticateExcepts []string

// 权限过滤 ["GET:passport/login"]
var permissionExcepts []string

// 初始化
func init() {
    once.Do(func() {
        // 登陆过滤
        authenticateExcepts = make([]string, 0)

        // 权限过滤
        permissionExcepts = make([]string, 0)
    })
}

// 添加登陆过滤
func AddAuthenticateExcept(name string) {
    authenticateExcepts = append(authenticateExcepts, name)
}

// 获取登陆过滤
func GetAuthenticateExcepts() []string {
    return authenticateExcepts
}

// 添加登陆过滤
func AddPermissionExcept(name string) {
    permissionExcepts = append(permissionExcepts, name)
}

// 获取登陆过滤
func GetPermissionExcepts() []string {
    return permissionExcepts
}

