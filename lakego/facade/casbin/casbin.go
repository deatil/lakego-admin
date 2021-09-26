package casbin

import (
    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/facade/database"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/casbin"
    casbinAdapter "lakego-admin/lakego/casbin/adapter"
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
    configfile := config.New("auth").GetString("Auth.RbacModel")
    modelConf := path.FormatPath(configfile)

    a, _ := casbinAdapter.NewAdapterByDB(newDb)

    c := &casbin.Casbin{}

    c.WithAdapter(a)
    c.WithModelConf(modelConf)

    return c
}
