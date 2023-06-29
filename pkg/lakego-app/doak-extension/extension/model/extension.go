package model

import (
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/uuid"
    "github.com/deatil/lakego-doak/lakego/facade"
)

type Extension struct {
    ID         string `gorm:"column:id;type:char(36);not null;primaryKey;" json:"id"`
    Name       string `gorm:"column:name;not null;type:varchar(160);" json:"name"`
    Title      string `gorm:"column:title;not null;type:varchar(200);" json:"title"`
    Info       string `gorm:"column:info;type:text;" json:"info"`
    Version    string `gorm:"column:version;type:text;" json:"version"`
    Adaptation string `gorm:"column:adaptation;type:text;" json:"adaptation"`
    Listorder  int    `gorm:"column:listorder;size:10;" json:"listorder"`
    Status     int    `gorm:"column:status;not null;" json:"status"`
    UpdateTime int    `gorm:"column:update_time;size:10;" json:"update_time"`
    UpdateIp   string `gorm:"column:update_ip;size:50;" json:"update_ip"`
    AddTime    int    `gorm:"column:add_time;size:10;" json:"add_time"`
    AddIp      string `gorm:"column:add_ip;size:50;" json:"add_ip"`
}

func (this *Extension) BeforeCreate(tx *gorm.DB) error {
    this.ID = uuid.ToUUIDString()

    return nil
}

func NewExtension() *gorm.DB {
    return facade.DB.Model(&Extension{})
}

func NewDB() *gorm.DB {
    return facade.DB
}

// 获取全部扩展
func GetAllExtensions() []map[string]any {
    list := make([]map[string]any, 0)

    NewExtension().
        Order("listorder DESC").
        Find(&list)

    return list
}

// 获取已启用扩展
func GetActiveExtensions() []map[string]any {
    list := make([]map[string]any, 0)

    NewExtension().
        Where("status = ?", 1).
        Order("listorder DESC").
        Find(&list)

    return list
}

// 获取信息
func GetExtension(name string) Extension {
    var info Extension

    // 模型
    NewExtension().
        Where("name = ?", name).
        First(&info)

    return info
}

func IsInstallExtension(name string) bool {
    info := GetExtension(name)

    if info.ID == "" {
        return false
    }

    return true
}

func IsEnableExtension(name string) bool {
    info := GetExtension(name)

    if info.ID == "" {
        return false
    }

    if info.Status != 1 {
        return false
    }

    return true
}
