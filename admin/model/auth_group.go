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
    ID              string      `gorm:"column:id;type:char(32);not null;primaryKey;" json:"id"`
    Parentid        string      `gorm:"column:parentid;type:char(32);not null;" json:"parentid" validate:"required"`
    Title           string      `gorm:"column:title;type:varchar(50);" json:"title" validate:"required"`
    Description     string      `gorm:"column:description;type:varchar(80);" json:"description"`
    Listorder       string      `gorm:"column:listorder;type:int(10);" json:"listorder"`
    Status          int         `gorm:"column:status;not null;type:tinyint(1);" json:"status" validate:"required,max=1,min=-1"`
    UpdateTime      int         `gorm:"column:update_time;type:int(10);" json:"update_time"`
    UpdateIp        string      `gorm:"column:update_ip;type:varchar(50);" json:"update_ip"`
    AddTime         int         `gorm:"column:add_time;type:int(10);" json:"add_time"`
    AddIp           string      `gorm:"column:add_ip;type:varchar(50);" json:"add_ip"`

    Admins []Admin `gorm:"many2many:auth_group_access;foreignKey:ID;joinForeignKey:GroupId;References:ID;JoinReferences:AdminId"`
    // Rules []AuthRule `gorm:"many2many:auth_rule_access;foreignKey:ID;joinForeignKey:GroupId;References:ID;JoinReferences:RuleId"`
}

func (m *AuthGroup) BeforeCreate(tx *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))
    m.ID = id

    return nil
}

func NewAuthGroup() *gorm.DB {
    return database.New().Model(&AuthGroup{})
}
