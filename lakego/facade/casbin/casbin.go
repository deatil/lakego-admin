package casbin

import (
    "lakego-admin/lakego/casbin"
)

/**
 * casbin
 *
 * @create 2021-6-20
 * @author deatil
 */
func New(model ...interface{}) *casbin.Casbin {
    return casbin.New(model...)
}

