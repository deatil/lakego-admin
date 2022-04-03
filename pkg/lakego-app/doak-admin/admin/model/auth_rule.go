package model

import (
    "time"
    "gorm.io/gorm"

    cast "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-hash/hash"
    
    "github.com/deatil/lakego-doak/lakego/random"
    "github.com/deatil/lakego-doak/lakego/facade/database"
)

// 菜单权限
type AuthRule struct {
    ID          string      `gorm:"column:id;size:32;not null;index;" json:"id"`
    Parentid    string      `gorm:"column:parentid;size:32;not null;" json:"parentid"`
    Title       string      `gorm:"column:title;not null;size:50;" json:"title"`
    Url         string      `gorm:"column:url;not null;" json:"url"`
    Method      string      `gorm:"column:method;not null;size:10;" json:"method"`
    Slug        string      `gorm:"column:slug;not null;size:50;" json:"slug"`
    Description string      `gorm:"column:description;" json:"description"`
    Listorder   string      `gorm:"column:listorder;size:10;" json:"listorder"`
    Status     	int         `gorm:"column:status;not null;" json:"status"`
    UpdateTime  int         `gorm:"column:update_time;size:10;" json:"update_time"`
    UpdateIp    string      `gorm:"column:update_ip;size:50;" json:"update_ip"`
    AddTime     int         `gorm:"column:add_time;size:10;" json:"add_time"`
    AddIp       string      `gorm:"column:add_ip;size:50;" json:"add_ip"`

    RuleAccesses []AuthRuleAccess `gorm:"foreignKey:RuleId;references:ID"`
}

func (this *AuthRule) BeforeCreate(tx *gorm.DB) error {
    this.ID = hash.MD5(cast.ToString(time.Nanosecond) + random.String(15))

    return nil
}

func NewAuthRule() *gorm.DB {
    return database.New().Model(&AuthRule{})
}
