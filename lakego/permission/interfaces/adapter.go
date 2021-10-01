package interfaces

import (
    "github.com/casbin/casbin/v2/model"
)

/**
 * 适配器接口
 *
 * @create 2021-9-8
 * @author deatil
 */
type Adapter interface {
    LoadFilteredPolicy(model model.Model, filter interface{}) error

    IsFiltered() bool

    SavePolicy(model model.Model) error

    AddPolicy(sec string, ptype string, rule []string) error

    RemovePolicy(sec string, ptype string, rule []string) error

    AddPolicies(sec string, ptype string, rules [][]string) error

    RemovePolicies(sec string, ptype string, rules [][]string) error

    RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error

    UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error

    // 关闭
    Close() error

    // 清空数据
    ClearData() error
}

