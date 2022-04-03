package adapter

import (
    "sync"
)

var instance *Path
var once sync.Once

// 单例
func InstancePath() *Path {
    once.Do(func() {
        instance = &Path{
            Pathes: make(PathesMap),
        }
    })

    return instance
}

type (
    // 路径类型
    PathesMap = map[string][]string
)

/**
 * 配置路径
 *
 * @create 2022-1-3
 * @author deatil
 */
type Path struct {
    // 路径
    Pathes PathesMap
}

// 添加
func (this *Path) WithPath(name string, path string) *Path {
    if _, ok := this.Pathes[name]; !ok {
        this.Pathes[name] = make([]string, 0)
    }

    this.Pathes[name] = append(this.Pathes[name], path)

    return this
}

// 获取
func (this *Path) GetPath(name string) []string {
    if paths, ok := this.Pathes[name]; ok {
        return paths
    }

    return make([]string, 0)
}
