package mysql

import (
    "fmt"
    "time"

    "database/sql"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
    "gorm.io/gorm/schema"

    "lakego-admin/lakego/logger"
)

type Mysql struct {
    db *gorm.DB
    sqlDB *sql.DB
    debug string
    config map[string]interface{}
}

func New(conf map[string]interface{}) *Mysql {
    return &Mysql{
        config: conf,
    }
}

/**
 * 设置调试
 */
func (m *Mysql) WithDebug(debug string) *Mysql {
    m.debug = debug
    return m
}

/**
 * 初始化
 */
func (m *Mysql) GetConnection() *gorm.DB {
    var dsn string

    // 配置
    conf := m.config

    // dsn 判断
    dsn = conf["dsn"].(string)
    if dsn == "" {
        dsn = m.GetMysqlDSN()
    }

    mc := mysql.Config{
        DSN:                       dsn,
        DefaultStringSize:         191,   // default length of string type field
        SkipInitializeWithVersion: false, // Automatic configuration based on version
        DisableDatetimePrecision:  true,  // Disable datetime precision. Databases before MySQL 5.6 do not support it.
        DontSupportRenameIndex:    true,
        DontSupportRenameColumn:   true,
    }

    db, err := gorm.Open(mysql.New(mc), &gorm.Config{
        NowFunc: func() time.Time {
            return time.Now().Local()
        },
        SkipDefaultTransaction: true,
        // disable foreign keys
        // specifying foreign keys does not create real foreign key constraints in mysql
        DisableForeignKeyConstraintWhenMigrating: true,
        NamingStrategy: schema.NamingStrategy{
            SingularTable: true,
            // 指定表前缀，修改默认表名
            TablePrefix: conf["prefix"].(string),
        },
        // query all fields, and in some cases "*" does not walk the index
        QueryFields: true,
    })

    if err != nil {
        logger.Fatalf("Error to open database[%s] connection: %v", mc.DSN, err)
    }

    // 连接池设置
    sqlDB, _ := db.DB()

    // 连接不活动时的最大生存时间
    sqlDB.SetConnMaxIdleTime(time.Second * 30)
    sqlDB.SetConnMaxLifetime(time.Duration(conf["connmaxlifetime"].(int)) * time.Second)

    MaxIdleConns := conf["maxidleconns"].(int)
    MaxOpenConns := conf["maxopenconns"].(int)

    // 连接超时相关
    sqlDB.SetMaxIdleConns(MaxIdleConns)
    sqlDB.SetMaxOpenConns(MaxOpenConns)

    if m.debug == "dev" {
        db = db.Debug()
    }

    m.db = db
    m.sqlDB = sqlDB

    return db
}

func (m *Mysql) CloseDb()  {
    if m.sqlDB.Ping() != nil {
        return
    }

    m.sqlDB.Close()
}

/**
 * 连接 DSN
 */
func (m *Mysql) GetMysqlDSN() string {
    // 配置
    conf := m.config

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

