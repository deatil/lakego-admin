package model

import (
    "gorm.io/gorm"
    "github.com/deatil/lakego-doak/lakego/facade/database"
)

// 管理员管理分组
type AuthGroupAccess struct {
    AdminId string `gorm:"column:admin_id;type:char(32);not null;index;" json:"admin_id"`
    GroupId string `gorm:"column:group_id;type:char(32);not null;index;" json:"group_id"`

    Admin Admin `gorm:"foreignKey:ID;references:AdminId"`
    Group AuthGroup `gorm:"foreignKey:ID;references:GroupId"`
}

func NewAuthGroupAccess() *gorm.DB {
    return database.New().Model(&AuthGroupAccess{})
}
