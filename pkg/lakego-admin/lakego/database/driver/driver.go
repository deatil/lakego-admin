package driver

import (
    "time"

    "gorm.io/gorm"
    "gorm.io/gorm/schema"

    "github.com/deatil/lakego-admin/lakego/logger"
    "github.com/deatil/lakego-admin/lakego/database/interfaces"
)

func New(conf ...map[string]interface{}) *Driver {
    d := &Driver{}

    if len(conf) > 0 {
        d.Config = conf[0]
    }

    return d
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
    Config map[string]interface{}
}

// 初始化
func (d *Driver) Init(config map[string]interface{}) interfaces.Driver {
    d.Config = config

    return d
}


// 设置配置
func (d *Driver) WithConfig(config map[string]interface{}) interfaces.Driver {
    d.Config = config

    return d
}

// 获取配置
func (d *Driver) GetConfig(name string) interface{} {
    if data, ok := d.Config[name]; ok {
        return data
    }

    return nil
}

/**
 * 初始化
 */
func (d *Driver) CreateConnection() {
}

/**
 * 初始化
 */
func (d *Driver) CreateOpenConnection(dia gorm.Dialector) {
    // 配置
    conf := d.Config

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
        logger.Fatalf("Error to open database connection: %v", err)
    }

    // 连接池设置, *sql.DB (database/sql)
    sqlDB, _ := db.DB()

    // 连接不活动时的最大生存时间
    sqlDB.SetConnMaxIdleTime(time.Second * 30)
    sqlDB.SetConnMaxLifetime(time.Duration(conf["connmaxlifetime"].(int)) * time.Second)

    MaxIdleConns := conf["maxidleconns"].(int)
    MaxOpenConns := conf["maxopenconns"].(int)

    // 连接超时相关
    sqlDB.SetMaxIdleConns(MaxIdleConns)
    sqlDB.SetMaxOpenConns(MaxOpenConns)

    d.db = db
}

/**
 * 初始化
 */
func (d *Driver) GetConnection() *gorm.DB {
    return d.db
}

/**
 * 获取数据库连接对象db，带debug
 */
func (d *Driver) GetConnectionWithDebug() *gorm.DB {
    return d.db.Debug()
}

/**
 * 关闭
 */
func (d *Driver) Close()  {
    sqlDB, _ := d.db.DB()

    if sqlDB.Ping() != nil {
        return
    }

    sqlDB.Close()
}

