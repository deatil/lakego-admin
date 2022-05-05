package driver

import (
    "log"
    "time"

    "gorm.io/gorm"
    "gorm.io/gorm/schema"

    "github.com/deatil/lakego-doak/lakego/database/interfaces"
)

func New(conf ...map[string]any) *Driver {
    driver := &Driver{}

    if len(conf) > 0 {
        driver.Config = conf[0]
    }

    return driver
}

/**
 * 基础驱动
 *
 * @create 2021-9-15
 * @author deatil
 */
type Driver struct {
    // gorm
    db *gorm.DB

    // 配置
    Config map[string]any
}

// 设置配置
func (this *Driver) WithConfig(config map[string]any) interfaces.Driver {
    this.Config = config

    return this
}

// 获取配置
func (this *Driver) GetConfig(name string) any {
    if data, ok := this.Config[name]; ok {
        return data
    }

    return nil
}

/**
 * 初始化
 */
func (this *Driver) CreateConnection() {
}

/**
 * 初始化
 */
func (this *Driver) CreateOpenConnection(dia gorm.Dialector) {
    // 配置
    conf := this.Config

    db, err := gorm.Open(dia, &gorm.Config{
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
        log.Printf("Error to open database connection: %v", err)
    }

    // 连接池设置, *sql.DB (database/sql)
    sqlDB, _ := db.DB()

    // 连接不活动时的最大生存时间
    sqlDB.SetConnMaxIdleTime(time.Second * 30)
    sqlDB.SetConnMaxLifetime(time.Duration(conf["conn-max-lifetime"].(int)) * time.Second)

    MaxIdleConns := conf["max-idle-conns"].(int)
    MaxOpenConns := conf["max-open-conns"].(int)

    // 连接超时相关
    sqlDB.SetMaxIdleConns(MaxIdleConns)
    sqlDB.SetMaxOpenConns(MaxOpenConns)

    this.db = db
}

/**
 * 初始化
 */
func (this *Driver) GetConnection() *gorm.DB {
    return this.db
}

/**
 * 获取数据库连接对象db，带debug
 */
func (this *Driver) GetConnectionWithDebug() *gorm.DB {
    return this.db.Debug()
}

/**
 * 关闭
 */
func (this *Driver) Close()  {
    sqlDB, _ := this.db.DB()

    if sqlDB.Ping() != nil {
        return
    }

    sqlDB.Close()
}

