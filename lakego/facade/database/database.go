package database

import (
    "sync"
    "gorm.io/gorm"

    "lakego-admin/lakego/database"
    "lakego-admin/lakego/facade/config"
)

var instance *database.Database
var once sync.Once

func GetInstance() *database.Database {
    once.Do(func() {
        instance = database.New()

        conf := config.New("database")

        instance.Connection(database.Config{
            Default: conf.GetString("Default"),
            Debug: conf.GetString("Debug"),
            Connections: conf.GetStringMap("Connections"),
        })
    })

    return instance
}

/**
 * 数据库
 *
 * @create 2021-7-11
 * @author deatil
 */
func New() *gorm.DB {
    db := GetInstance()

    return db.GetDB()
}


/**
 * 数据库，自定义类型
 *
 * @create 2021-7-11
 * @author deatil
 */
func NewWithType(typeName string) *gorm.DB {
    db := database.New()

    conf := config.New("database")

    db.Connection(database.Config{
        Default: typeName,
        Debug: conf.GetString("Debug"),
        Connections: conf.GetStringMap("Connections"),
    })

    return db.GetDB()
}

