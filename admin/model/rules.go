package model

import (
    "time"
    "strconv"
    "gorm.io/gorm"

    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/facade/database"
)

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

func (rules *Rules) BeforeCreate(db *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))
    rules.ID = id

    return nil
}

func NewRules() *gorm.DB {
    return database.New().Model(&Rules{})
}

