package casbin

import (
    casbiner "github.com/casbin/casbin/v2"

    casbinAdapter "lakego-admin/lakego/casbin/adapter"
    "lakego-admin/lakego/facade/database"
    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/casbin"
)

/**
 * casbin
 *
 * @create 2021-6-20
 * @author deatil
 */
func New() *casbin.Casbin {
    newDb := database.New()

    // 配置文件路径
    configPath := path.GetBasePath()
    modelConf := configPath + "/config/rbac_model.conf"

    a, _ := casbinAdapter.NewAdapterByDB(newDb)
    e, _ := casbiner.NewEnforcer(modelConf, a)

    // Load the policy from DB.
    // e.LoadPolicy()

    // Save the policy back to DB.
    // e.SavePolicy()

    c := &casbin.Casbin{
        Enforcer: e,
    }

    return c
}
