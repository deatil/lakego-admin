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
    LoadPolicy(model.Model) error

    LoadFilteredPolicy(model.Model, any) error

    IsFiltered() bool

    SavePolicy(model.Model) error

    AddPolicy(string, string, []string) error

    RemovePolicy(string, string, []string) error

    AddPolicies(string, string, [][]string) error

    RemovePolicies(string, string, [][]string) error

    RemoveFilteredPolicy(string, string, int, ...string) error

    UpdatePolicy(string, string, []string, []string) error
}

