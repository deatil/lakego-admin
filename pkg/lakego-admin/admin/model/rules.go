package model

import (
    "time"
    "strconv"
    "gorm.io/gorm"

    "github.com/deatil/lakego-admin/lakego/support/hash"
    "github.com/deatil/lakego-admin/lakego/support/random"
    "github.com/deatil/lakego-admin/lakego/facade/database"
)

// 授权权限
type Rules struct {
    ID    string `gorm:"primaryKey;autoIncrement:false;size:32"`
    Ptype string `gorm:"size:250;"`
    V0    string `gorm:"size:250;"`
    V1    string `gorm:"size:250;"`
    V2    string `gorm:"size:250;"`
    V3    string `gorm:"size:250;"`
    V4    string `gorm:"size:250;"`
    V5    string `gorm:"size:250;"`
}

func (this *Rules) BeforeCreate(db *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10) + random.String(10))
    this.ID = id

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
