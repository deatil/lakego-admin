package model

import (
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/uuid"
    "github.com/deatil/lakego-doak/lakego/facade"
)

type Extension struct {
    ID         string `gorm:"column:id;type:char(36);not null;primaryKey;" json:"id"`
    Name       string `gorm:"column:name;not null;type:varchar(250);" json:"name"`
    Info       string `gorm:"column:info;type:text;" json:"info"`
    Listorder  string `gorm:"column:listorder;size:10;" json:"listorder"`
    Status     int    `gorm:"column:status;not null;" json:"status"`
    UpdateTime int    `gorm:"column:update_time;size:10;" json:"update_time"`
    UpdateIp   string `gorm:"column:update_ip;size:50;" json:"update_ip"`
    AddTime    int    `gorm:"column:add_time;size:10;" json:"add_time"`
    AddIp      string `gorm:"column:add_ip;size:50;" json:"add_ip"`
}

func (this *Extension) BeforeCreate(tx *gorm.DB) error {
    this.ID = uuid.ToUUIDString()

    return nil
}

func NewExtension() *gorm.DB {
    return facade.DB.Model(&Extension{})
}

func NewDB() *gorm.DB {
    return facade.DB
}

