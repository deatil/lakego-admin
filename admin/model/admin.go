package model

import (
	"time"
	"strconv"
	"gorm.io/gorm"
	
	"lakego-admin/lakego/support/hash"
	"lakego-admin/lakego/database"
)

type Admin struct {
	ID             	string      `gorm:"column:id;size:32;not null;index;" json:"id"`
	Name           	string      `gorm:"column:name;not null;" json:"name" validate:"required"`
	Password       	string      `gorm:"column:password;" json:"password" validate:"required"`
	PasswordSalt   	string      `gorm:"column:password_salt;" json:"password_salt" validate:"required"`
	Nickname       	string      `gorm:"column:nickname;" json:"nickname" validate:"required"`
	Email          	string      `gorm:"column:email;size:40;" json:"email"`
	Avatar   		string      `gorm:"column:avatar;size:32;" json:"avatar"`
	Status     		int         `gorm:"column:status;not null;size:1;" json:"status" validate:"required,max=1,min=-1"`
	LastLoginTime   int      	`gorm:"column:last_login_time;size:10;" json:"last_login_time"`
	LastLoginIp     string      `gorm:"column:last_login_ip;size:50;" json:"last_login_ip"`
	UpdateTime     	int      	`gorm:"column:update_time;size:10;" json:"update_time"`
	UpdateIp     	string      `gorm:"column:update_ip;size:50;" json:"update_ip"`
	AddTime     	int      	`gorm:"column:add_time;size:10;" json:"add_time"`
	AddIp     		string      `gorm:"column:add_ip;size:50;" json:"add_ip"`
	
	Attachments []Attachment `gorm:"polymorphic:Owner;polymorphicValue:admin"`
	AuthGroups []AuthGroup `gorm:"many2many:AuthGroupAccess;foreignKey:ID;joinForeignKey:AdminId;References:ID;JoinReferences:GroupId"`
}

func (m *Admin) BeforeCreate(tx *gorm.DB) error {
	id := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))
	m.ID = id
	
	return nil
}

func NewAdmin() *gorm.DB {
	return database.GetDB().Model(&Admin{})
}
