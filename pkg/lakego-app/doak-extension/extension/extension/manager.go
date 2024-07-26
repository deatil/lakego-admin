package extension

import (
    "sync"
    "errors"
    "encoding/json"

    "github.com/deatil/go-events/events"

    "github.com/deatil/lakego-doak/lakego/str"
    "github.com/deatil/lakego-doak/lakego/router"
    iapp "github.com/deatil/lakego-doak/lakego/app/interfaces"
    admin_route "github.com/deatil/lakego-doak-admin/admin/support/route"

    "github.com/deatil/lakego-doak-extension/extension/model"
)

// 默认
var defaultManager = NewManager()

// 单例
func GetManager() *Manager {
    return defaultManager
}

// 扩展管理
type Manager struct {
    // 锁定
    mu sync.RWMutex

    // 名称
    extensions map[string]Extension

    // 事件名称
    eventBootingName string

    // 事件名称
    eventBootedName string
}

// 初始化
func NewManager() *Manager {
    m := &Manager{}
    m.extensions = make(map[string]Extension)
    m.eventBootingName = "lakego-admin:booting"
    m.eventBootedName = "lakego-admin:booted"

    return m
}

// 添加扩展
func (this *Manager) Extend(ext Extension) *Manager {
    this.mu.Lock()
    defer this.mu.Unlock()

    if ext.Name != "" {
        this.extensions[ext.Name] = ext
    }

    return this
}

// 添加扩展
func Extend(ext Extension) *Manager {
    return defaultManager.Extend(ext)
}

// 获取扩展
func (this *Manager) GetExtend(name string) (Extension, error) {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if ext, ok := this.extensions[name]; ok {
        return ext, nil
    }

    return Extension{}, errors.New("no ext")
}

// 获取全部添加的扩展
func (this *Manager) GetAllExtend() map[string]Extension {
    return this.extensions
}

// 判断
func (this *Manager) Exists(name string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    _, exists := this.extensions[name]

    return exists
}

// 移除添加的扩展
func (this *Manager) Forget(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.extensions, name)
}

// Booting
func (this *Manager) Booting(callback func()) {
    events.AddAction(this.eventBootingName, callback, events.DefaultSort)
}

// Booting
func Booting(callback func()) {
    defaultManager.Booting(callback)
}

// Booted
func (this *Manager) Booted(callback func()) {
    events.AddAction(this.eventBootedName, callback, events.DefaultSort)
}

// Booted
func Booted(callback func()) {
    defaultManager.Booted(callback)
}

// CallBooting
func (this *Manager) CallBooting() {
    events.DoAction(this.eventBootingName)
}

// CallBooted
func (this *Manager) CallBooted() {
    events.DoAction(this.eventBootedName)
}

// 设置扩展路由
func (this *Manager) Routes(fn func(*router.RouterGroup)) {
    // 后台路由
    admin_route.AddRoute(func(engine *router.RouterGroup) {
        fn(engine)
    })
}

// 加载扩展
func (this *Manager) BootExtension(ia iapp.App) {
    exts := model.GetActiveExtensions()

    for _, ext := range exts {
        info := this.GetExtension(ext["name"].(string))
        if info.Name != "" && info.Start != nil {
            info.Start(ia)
        }
    }
}

// 扩展配置信息
func (this *Manager) GetExtension(name string) Extension {
    info, err := this.GetExtend(name)
    if err == nil {
        return info
    }

    return Extension{}
}

// 全部添加的扩展
func (this *Manager) GetExtensions() []Extension {
    exts := make([]Extension, 0)

    for _, ext := range this.extensions {
        if ext.Name != "" {
            exts = append(exts, ext)
        }
    }

    return exts
}

// 验证信息
func (this *Manager) ValidateInfo(info Extension) bool {
    var data map[string]any
    err := json.Unmarshal(info.ToJSON(), &data)
    if err != nil {
        return false
    }

    mustInfo := []string{
        "title",
        "description",
        "keywords",
        "authors",
        "version",
        "adaptation",
    }

    for _, v := range mustInfo {
        if _, ok := data[v]; !ok {
            return false;
        }

        if str.Empty(data[v]) {
            return false;
        }
    }

    return true;
}
