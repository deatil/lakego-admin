package model

import (
    "time"
    "strconv"
    "gorm.io/gorm"

    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/facade/database"
)

// 权限分组
type AuthGroup struct {
    ID              string      `gorm:"column:id;size:32;not null;index;" json:"id"`
    Parentid        string      `gorm:"column:parentid;size:32;not null;" json:"parentid" validate:"required"`
    Title           string      `gorm:"column:title;size:50;" json:"title" validate:"required"`
    Description     string      `gorm:"column:description;" json:"description"`
    Listorder       string      `gorm:"column:listorder;size:10;" json:"listorder"`
    Status          int         `gorm:"column:status;not null;size:1;" json:"status" validate:"required,max=1,min=-1"`
    UpdateTime      int         `gorm:"column:update_time;size:10;" json:"update_time"`
    UpdateIp        string      `gorm:"column:update_ip;size:50;" json:"update_ip"`
    AddTime         int         `gorm:"column:add_time;size:10;" json:"add_time"`
    AddIp           string      `gorm:"column:add_ip;size:50;" json:"add_ip"`

    Rules []AuthRule `gorm:"column:rules;many2many:auth_rule_access;foreignKey:ID;joinForeignKey:GroupId;References:ID;JoinReferences:RuleId"`
}

func (m *AuthGroup) BeforeCreate(tx *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))
    m.ID = id

    return nil
}

func NewAuthGroup() *gorm.DB {
    return database.New().Model(&AuthGroup{})
}
