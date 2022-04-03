package model

import (
    "time"
    "gorm.io/gorm"

    cast "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-hash/hash"
    
    "github.com/deatil/lakego-doak/lakego/random"
    "github.com/deatil/lakego-doak/lakego/facade/database"
)

type Admin struct {
    ID              string      `gorm:"column:id;type:char(32);not null;primaryKey;" json:"id"`
    Name            string      `gorm:"column:name;not null;type:varchar(30);" json:"name"`
    Password        string      `gorm:"column:password;type:char(32);" json:"password"`
    PasswordSalt    string      `gorm:"column:password_salt;type:char(6);" json:"password_salt"`
    Nickname        string      `gorm:"column:nickname;type:varchar(150);" json:"nickname"`
    Email           string      `gorm:"column:email;type:varchar(100);" json:"email"`
    Avatar          string      `gorm:"column:avatar;type:char(32);" json:"avatar"`
    Introduce       string      `gorm:"column:introduce;type:mediumtext;" json:"introduce"`
    IsRoot          int         `gorm:"column:is_root;type:tinyint(1);" json:"is_root"`
    Status          int         `gorm:"column:status;not null;type:tinyint(1);" json:"status"`
    RefreshTime     int         `gorm:"column:refresh_time;type:int(10);" json:"refresh_time"`
    RefreshIp       string      `gorm:"column:refresh_ip;type:varchar(50);" json:"refresh_ip"`
    LastActive      int         `gorm:"column:last_active;type:int(10);" json:"last_active"`
    LastIp          string      `gorm:"column:last_ip;type:varchar(50);" json:"last_ip"`
    UpdateTime      int         `gorm:"column:update_time;type:int(10);" json:"update_time"`
    UpdateIp        string      `gorm:"column:update_ip;type:varchar(50);" json:"update_ip"`
    AddTime         int         `gorm:"column:add_time;type:int(10);" json:"add_time"`
    AddIp           string      `gorm:"column:add_ip;type:varchar(50);" json:"add_ip"`

    Groups []AuthGroup `gorm:"many2many:auth_group_access;foreignKey:ID;joinForeignKey:AdminId;References:ID;JoinReferences:GroupId"`
    Attachments []Attachment `gorm:"polymorphic:Owner;polymorphicValue:admin;"`
    GroupAccesses []AuthGroupAccess `gorm:"foreignKey:AdminId;references:ID"`
}

func (this *Admin) BeforeCreate(tx *gorm.DB) error {
    this.ID = hash.MD5(cast.ToString(time.Nanosecond) + random.String(15))

    return nil
}

func NewAdmin() *gorm.DB {
    return database.New().Model(&Admin{})
}

