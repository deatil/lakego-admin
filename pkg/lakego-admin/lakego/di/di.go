package di

import (
    "sync"
    "go.uber.org/fx"
)

/**
 * 容器
 *
 * @create 2021-10-20
 * @author deatil
 */
type DI struct {
    // 锁
    Lock *sync.RWMutex

    // 别名
    Aliases map[string]string

    // 别名
    AbstractAliases map[string][]string

    // 绑定
    Bindings map[string]func(interface{})

    // 单例绑定
    Instances map[string]func(interface{})
}

// 绑定
func (this *DI) Bind(abstract string, concrete interface{}) {
    fx.Provide(concrete)

    this.Bindings[abstract] = func(name interface{}) {
        fx.Populate(name)
    }

}

// 单例绑定
func (this *DI) Singleton(abstract string, concrete interface{}) {

}

// make
func (this *DI) Make(abstract string, parameters map[string]interface{}) {

}

// get
func (this *DI) Get(id string) {

}

// get
func (this *DI) Resolve(id string, parameters map[string]interface{}) {

}

// 判断
func (this *DI) Bound(abstract string) bool {
    return true
}

// 别名
func (this *DI) Alias(abstract string, alias string) {
    if abstract == alias {
        panic("不能绑定自己")
    }

    this.Aliases[abstract] = alias

    this.AbstractAliases[abstract] = append(this.AbstractAliases[abstract], alias)
}

// 判断
func (this *DI) Has(abstract string) bool {
    return this.bound(abstract)
}

// 判断别名
func (this *DI) isAlias(abstract string) bool {
    if _, ok := this.Aliases[abstract]; ok {
        return true
    }

    return false
}

// 判断
func (this *DI) GetAlias(abstract string) bool {
    if name, ok := this.Aliases[abstract]; ok {
        return this.getAlias(name)
    }

    return abstract
}

// Bindings
func (this *DI) GetBindings(abstract string) map[string]func(string, interface{}) {
    return this.Bindings
}

// 移除单个
func (this *DI) forgetInstance(abstract string) {
    delete(this.Instances, abstract)
}

// 全部移除
func (this *DI) forgetInstances(abstract string) {
    this.Instances = make(map[string]func(string, interface{}))
}

