package model

import (
    "time"
    "strconv"
    "gorm.io/gorm"

    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/facade/database"
)

// 附件
type Attachment struct {
    ID              string      `gorm:"column:id;size:32;not null;index;" json:"id"`
    OwnerType       string      `gorm:"column:owner_type;size:50;not null;" json:"type"`
    OwnerID         string      `gorm:"column:owner_id;size:32;" json:"type_id"`
    Name            string      `gorm:"column:name;size:50;" json:"name"`
    Path            string      `gorm:"column:path;size:255;" json:"path"`
    Mime            string      `gorm:"column:mime;size:100;" json:"mime"`
    Extension       string      `gorm:"column:extension;size:10;" json:"extension"`
    Size            string      `gorm:"column:size;size:100;" json:"size"`
    Md5             string      `gorm:"column:md5;size:32;" json:"md5"`
    Sha1            string      `gorm:"column:sha1;size:40;" json:"sha1"`
    Driver          string      `gorm:"column:driver;size:16;" json:"driver"`
    Status          int         `gorm:"column:status;not null;size:1;" json:"status"`
    UpdateTime      int         `gorm:"column:update_time;size:10;" json:"update_time"`
    CreateTime      int         `gorm:"column:create_time;size:10;" json:"create_time"`
    AddTime         int         `gorm:"column:add_time;size:10;" json:"add_time"`
    AddIp           string      `gorm:"column:add_ip;size:50;" json:"add_ip"`
}

func (m *Attachment) BeforeCreate(tx *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))
    m.ID = id

    return nil
}

func NewAttachment() *gorm.DB {
    return database.New().Model(&Attachment{})
}
