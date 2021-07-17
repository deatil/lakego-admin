package model

import (
    "gorm.io/gorm"

    "lakego-admin/lakego/facade/database"
)

func NewDB() *gorm.DB {
    return database.New()
}

