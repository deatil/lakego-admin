package model

import (
    "time"
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/support/cast"
    "github.com/deatil/lakego-doak/lakego/support/hash"
    "github.com/deatil/lakego-doak/lakego/support/random"
    "github.com/deatil/lakego-doak/lakego/support/snowflake"
    "github.com/deatil/lakego-doak/lakego/facade/database"
)

type ActionLog struct {
    ID          string      `gorm:"column:id;type:char(32);not null;primaryKey;" json:"id"`
    Name        string      `gorm:"column:name;not null;type:varchar(250);" json:"name"`
    Url         string      `gorm:"column:url;type:text;" json:"url"`
    Method      string      `gorm:"column:method;type:varchar(10);" json:"method"`
    Info        string      `gorm:"column:info;type:text;" json:"info"`
    Useragent   string      `gorm:"column:useragent;type:text;" json:"useragent"`
    Time        int         `gorm:"column:time;type:int(10);" json:"time"`
    Ip          string      `gorm:"column:ip;type:varchar(50);" json:"ip"`
    Status      string      `gorm:"column:status;type:char(3);" json:"status"`
}

func (this *ActionLog) BeforeCreate(tx *gorm.DB) error {
    snowflakeId, _ := snowflake.Make(5)
    this.ID = hash.MD5(cast.ToString(snowflakeId) + cast.ToString(time.Nanosecond) + random.String(15))

    return nil
}

func NewActionLog() *gorm.DB {
    return database.New().Model(&ActionLog{})
}

