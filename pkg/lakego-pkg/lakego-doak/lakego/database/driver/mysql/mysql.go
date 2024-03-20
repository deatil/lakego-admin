package mysql

import (
    "gorm.io/driver/mysql"

    "github.com/deatil/lakego-doak/lakego/database/driver"
)

/**
 * Mysql 驱动
 *
 * @create 2021-9-15
 * @author deatil
 */
type Mysql struct {
    // 继承默认
    driver.Driver
}

// 构造函数
func New(conf ...map[string]any) *Mysql {
    m := &Mysql{}

    if len(conf) > 0 {
        m.Config = conf[0]
    }

    m.CreateConnection()

    return m
}

// 创建连接
func (this *Mysql) CreateConnection() {
    var dsn string

    // 配置
    conf := this.Config

    // 连接配置
    dsn = conf["dsn"].(string)

    mc := mysql.Config{
        DSN:                       dsn,
        DefaultStringSize:         191,   // default length of string type field
        SkipInitializeWithVersion: false, // Automatic configuration based on version
        DisableDatetimePrecision:  true,  // Disable datetime precision. Databases before MySQL 5.6 do not support it.
        DontSupportRenameIndex:    true,
        DontSupportRenameColumn:   true,
    }

    // 创建链接
    dialector := mysql.New(mc)

    this.CreateOpenConnection(dialector)
}
