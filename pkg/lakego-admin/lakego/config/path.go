package config

import (
    "sync"
)

var instance *Path
var once sync.Once

// 单例
func NewPathInstance() *Path {
    once.Do(func() {
        instance = &Path{}
    })

    return instance
}

/**
 * 配置路径
 *
 * @create 2022-1-3
 * @author deatil
 */
type Path struct {
    // 路径
    Pathes []string
}

// 添加适配器
func (this *Path) WithPath(path string) *Path {
    this.Pathes = append(this.Pathes, path)

    return this
}

// 获取适配器
func (this *Path) GetPathes() []string {
    return this.Pathes
}
