package model

import (
    "time"
    "strconv"
    "gorm.io/gorm"
    
    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/database"
)

// 菜单权限
type AuthRule struct {
    ID          string      `gorm:"column:id;size:32;not null;index;" json:"id"`
    Parentid    string      `gorm:"column:parentid;size:32;not null;" json:"parentid"`
    Title       string      `gorm:"column:title;not null;size:50;" json:"title" validate:"required"`
    Url       	string      `gorm:"column:url;not null;" json:"url" validate:"required"`
    Method   	string      `gorm:"column:method;not null;size:10;" json:"method"`
    Remark      string      `gorm:"column:remark;" json:"remark"`
    Listorder   string      `gorm:"column:listorder;size:10;" json:"listorder"`
    Status     	int         `gorm:"column:status;not null;" json:"status" validate:"required,max=1,min=-1"`
    UpdateTime  int      	`gorm:"column:update_time;size:10;" json:"update_time"`
    UpdateIp    string      `gorm:"column:update_ip;size:50;" json:"update_ip"`
    AddTime     int      	`gorm:"column:add_time;size:10;" json:"add_time"`
    AddIp     	string      `gorm:"column:add_ip;size:50;" json:"add_ip"`
}

func (m *AuthRule) BeforeCreate(tx *gorm.DB) error {
    id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))
    m.ID = id
    
    return nil
}

func NewAuthRule() *gorm.DB {
    return database.GetDB().Model(&AuthRule{})
}
