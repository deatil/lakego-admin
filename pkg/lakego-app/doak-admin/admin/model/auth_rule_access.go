package model

import (
    "gorm.io/gorm"
    "github.com/deatil/lakego-doak/lakego/facade/database"
)

// 分组关联菜单权限
type AuthRuleAccess struct {
    GroupId string `gorm:"column:group_id;size:36;not null;index;" json:"group_id"`
    RuleId 	string `gorm:"column:rule_id;size:36;not null;index;" json:"rule_id"`

    Rule AuthRule `gorm:"foreignKey:ID;references:RuleId"`
    Group AuthGroup `gorm:"foreignKey:ID;references:GroupId"`
}

// 自定义表名
func (this *AuthRuleAccess) TableName() string {
    return "lakego_auth_rule_access"
}

func NewAuthRuleAccess() *gorm.DB {
    return database.New().Model(&AuthRuleAccess{})
}
