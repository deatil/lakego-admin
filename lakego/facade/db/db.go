package db

import (
	"gorm.io/gorm"
	"lakego-admin/lakego/database"
)

/**
 * 数据库
 *
 * @create 2021-6-20
 * @author deatil
 */
func New() *gorm.DB {
	return database.GetDB()
}

