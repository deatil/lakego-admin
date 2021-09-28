package model

import (
    "time"
    "strconv"
    "gorm.io/gorm"

    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/support/random"
    "lakego-admin/lakego/facade/database"
)

type ActionLog struct {
    ID          string      `gorm:"column:id;type:char(32);not null;primaryKey;" json:"id"`
    Name        string      `gorm:"column:name;not null;type:varchar(250);" json:"name"`
    Url         string      `gorm:"column:url;type:text;" json:"url"`
    Method      string      `gorm:"column:method;type:varchar(10);" json:"method"`
    Info        string      `gorm:"column:info;type:text;" json:"info"`
    Useragent   string      `gorm:"column:useragent;type:text;" json:"useragent"`
    Ip          string      `gorm:"column:ip;type:varchar(50);" json:"ip"`
    AddTime     int         `gorm:"column:add_time;type:int(10);" json:"add_time"`
    AddIp       string      `gorm:"column:add_ip;type:varchar(50);" json:"add_ip"`
}

func (m *ActionLog) BeforeCreate(tx *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10) + random.String(10))
    m.ID = id

    return nil
}

func NewActionLog() *gorm.DB {
    return database.New().Model(&ActionLog{})
}

