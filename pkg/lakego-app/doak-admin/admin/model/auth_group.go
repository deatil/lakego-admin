package model

import (
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/uuid"
)

// 权限分组
type AuthGroup struct {
    ID          string `gorm:"column:id;type:char(36);not null;primaryKey;" json:"id"`
    Parentid    string `gorm:"column:parentid;type:char(36);not null;" json:"parentid"`
    Title       string `gorm:"column:title;type:varchar(50);" json:"title"`
    Description string `gorm:"column:description;type:varchar(80);" json:"description"`
    Listorder   int    `gorm:"column:listorder;type:int(10);" json:"listorder"`
    Status      int    `gorm:"column:status;not null;type:tinyint(1);" json:"status"`
    UpdateTime  int    `gorm:"column:update_time;type:int(10);" json:"update_time"`
    UpdateIp    string `gorm:"column:update_ip;type:varchar(50);" json:"update_ip"`
    AddTime     int    `gorm:"column:add_time;type:int(10);" json:"add_time"`
    AddIp       string `gorm:"column:add_ip;type:varchar(50);" json:"add_ip"`

    Admins []Admin `gorm:"many2many:auth_group_access;foreignKey:ID;joinForeignKey:GroupId;References:ID;JoinReferences:AdminId"`
    Rules []AuthRule `gorm:"many2many:auth_rule_access;foreignKey:ID;joinForeignKey:GroupId;References:ID;JoinReferences:RuleId"`

    RuleAccesses []AuthRuleAccess `gorm:"foreignKey:GroupId;references:ID"`
    GroupAccesses []AuthGroupAccess `gorm:"foreignKey:GroupId;references:ID"`
}

func (this *AuthGroup) BeforeCreate(tx *gorm.DB) error {
    this.ID = uuid.ToUUIDString()

    return nil
}

func NewAuthGroup() *gorm.DB {
    return NewDB().Model(&AuthGroup{})
}
