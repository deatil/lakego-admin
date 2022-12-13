package model

import (
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/uuid"
    "github.com/deatil/lakego-doak/lakego/facade/database"
)

// 授权权限
type Rules struct {
    ID    string `gorm:"primaryKey;autoIncrement:false;size:36"`
    Ptype string `gorm:"size:250;"`
    V0    string `gorm:"size:250;"`
    V1    string `gorm:"size:250;"`
    V2    string `gorm:"size:250;"`
    V3    string `gorm:"size:250;"`
    V4    string `gorm:"size:250;"`
    V5    string `gorm:"size:250;"`
}

func (this *Rules) BeforeCreate(db *gorm.DB) error {
    this.ID = uuid.ToUUIDString()

    return nil
}

func NewRules() *gorm.DB {
    return database.New().Model(&Rules{})
}

// 清空数据
func ClearRulesData() error {
    err := NewRules().
        Where("1 = 1").Delete(&Rules{}).
        Error

    return err
}
