package publish

import (
    "sync"
    "reflect"
)

var instance *Publish
var once sync.Once

// 单例
func Instance() *Publish {
    once.Do(func() {
        instance = New()
    })

    return instance
}

// 构造函数
func New() *Publish {
    return &Publish{
        Publishes: make(PublishesMap),
        PublishGroups: make(PublishGroupsMap),
    }
}

type (
    // 要推送的目录
    PublishesMap = map[string]map[string]string

    // 分组
    PublishGroupsMap = map[string]map[string]string
)

/**
 * 推送
 *
 * @create 2022-1-1
 * @author deatil
 */
type Publish struct {
    // 要推送的目录
    Publishes PublishesMap

    // 分组
    PublishGroups PublishGroupsMap
}

// 添加推送
func (this *Publish) Publish(class interface{}, paths map[string]string, group string) *Publish {
    className := this.GetStructName(class)

    this.EnsurePublishArrayInitialized(className)

    for k, v := range paths {
        this.Publishes[className][k] = v
    }

    this.AddPublishGroup(group, paths)

    return this
}

// 初始化
func (this *Publish) EnsurePublishArrayInitialized(class string) *Publish {
    if _, ok := this.Publishes[class]; !ok {
        this.Publishes[class] = make(map[string]string)
    }

    return this
}

// AddPublishGroup
func (this *Publish) AddPublishGroup(group string, paths map[string]string) *Publish {
    if _, ok := this.PublishGroups[group]; !ok {
        this.PublishGroups[group] = make(map[string]string)
    }

    for pk, pv := range paths {
        this.PublishGroups[group][pk] = pv
    }

    return this
}

// PathsToPublish
func (this *Publish) PathsToPublish(provider string, group string) map[string]string {
    paths := this.PathsForProviderOrGroup(provider, group)
    if paths != nil {
        return paths
    }

    dataMap := make(map[string]string)

    for _, publishesData := range this.Publishes {
        for publicKey, publicData := range publishesData {
            dataMap[publicKey] = publicData
        }
    }

    return dataMap
}

// PathsForProviderOrGroup
func (this *Publish) PathsForProviderOrGroup(provider string, group string) map[string]string {
    dataMap := make(map[string]string)

    if provider != "" && group != "" {
        return this.PathsForProviderAndGroup(provider, group)
    } else if group != "" {
        if publishGroupsData, ok := this.PublishGroups[group]; ok {
            return publishGroupsData
        }

        return dataMap
    } else if provider != "" {
        if publishesData, ok := this.Publishes[provider]; ok {
            return publishesData
        }

        return dataMap
    }

    return nil
}

// PathsForProviderAndGroup
func (this *Publish) PathsForProviderAndGroup(provider string, group string) map[string]string {
    dataMap := make(map[string]string)

    if _, ok := this.Publishes[provider]; !ok {
        return dataMap
    }

    if _, ok2 := this.PublishGroups[group]; !ok2 {
        return dataMap
    }

    newProviderData := this.Publishes[provider]
    for gk, _ := range this.PublishGroups[group] {
        if _, ok3 := newProviderData[gk]; ok3 {
            dataMap[gk] = newProviderData[gk]
        }
    }

    return dataMap
}

// PublishableProviders
func (this *Publish) PublishableProviders() []string {
    arr := make([]string, 0)

    for k, _ := range this.Publishes {
        arr = append(arr, k)
    }

    return arr
}

// PublishableGroups
func (this *Publish) PublishableGroups() []string {
    arr := make([]string, 0)

    for k, _ := range this.PublishGroups {
        arr = append(arr, k)
    }

    return arr
}

// 反射获取结构体名称
func (this *Publish) GetStructName(name interface{}) string {
    elem := reflect.TypeOf(name).Elem()

    return elem.PkgPath() + "." + elem.Name()
}

