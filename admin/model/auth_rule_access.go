package model

import (
    "gorm.io/gorm"
    "lakego-admin/lakego/database"
)

// 分组关联菜单权限
type AuthRuleAccess struct {
    GroupId string `gorm:"column:group_id;size:32;not null;index;" json:"group_id"`
    RuleId 	string `gorm:"column:rule_id;size:32;not null;index;" json:"rule_id"`
}

func NewAuthRuleAccess() *gorm.DB {
    return database.GetDB().Model(&AuthRuleAccess{})
}
