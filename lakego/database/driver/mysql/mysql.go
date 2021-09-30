package mysql

import (
    "fmt"

    "gorm.io/driver/mysql"

    "lakego-admin/lakego/database/driver"
)

func New(conf ...map[string]interface{}) *Mysql {
    m := &Mysql{}

    if len(conf) > 0 {
        m.Config = conf[0]
    }

    return m
}

type Mysql struct {
    // 继承默认
    driver.Driver
}

/**
 * 初始化
 */
func (m *Mysql) CreateConnection() {
    var dsn string

    // 配置
    conf := m.Config

    // dsn 判断
    dsn = conf["dsn"].(string)
    if dsn == "" {
        dsn = m.getDSN()
    }

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

    m.CreateOpenConnection(dialector)
}

/**
 * 连接 DSN
 */
func (m *Mysql) getDSN() string {
    // 配置
    conf := m.Config

    Host := conf["host"].(string)
    Port := conf["port"].(int)
    Username := conf["username"].(string)
    Password := conf["password"].(string)
    Charset := conf["charset"].(string)
    Database := conf["database"].(string)

    return fmt.Sprintf(
        "%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local",
        Username,
        Password,
        Host,
        Port,
        Database,
        Charset,
    )
}

