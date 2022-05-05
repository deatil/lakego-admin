package adapter

import (
    "github.com/casbin/casbin/v2/model"
)

/**
 * 适配器
 *
 * @create 2021-9-9
 * @author deatil
 */
type Adapter struct {
    //
}

func (this *Adapter) LoadPolicy(model model.Model) error {
    panic("接口没有被实现")
}

func (this *Adapter) LoadFilteredPolicy(model model.Model, filter any) error {
    panic("接口没有被实现")
}

func (this *Adapter) IsFiltered() bool {
    panic("接口没有被实现")
}

func (this *Adapter) SavePolicy(model model.Model) error {
    panic("接口没有被实现")
}

func (this *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
    panic("接口没有被实现")
}

func (this *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
    panic("接口没有被实现")
}

func (this *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
    panic("接口没有被实现")
}

func (this *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
    panic("接口没有被实现")
}

func (this *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
    panic("接口没有被实现")
}

func (this *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
    panic("接口没有被实现")
}

