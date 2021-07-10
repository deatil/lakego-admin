package driver

import (
    "fmt"
    "time"
    
    "database/sql"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
    "gorm.io/gorm/schema"

    "lakego-admin/lakego/logger"
    "lakego-admin/lakego/database/config"
)

var db *gorm.DB
var sqlDB *sql.DB
var err error 

/**
 * 初始化
 */
func GetMysqlConnection(typeName string) *gorm.DB {
    var dsn string
    
    // dsn 判断
    dsn = config.New(typeName).GetString("Dsn")
    if dsn == "" {
        dsn = GetMysqlDSN(typeName)
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
            TablePrefix: config.New(typeName).GetString("Prefix"),
        },
        // query all fields, and in some cases "*" does not walk the index
        QueryFields: true,
    })

    if err != nil {
        logger.Fatalf("Error to open database[%s] connection: %v", mc.DSN, err)
    }
    
    // 连接池设置
    sqlDB, _ = db.DB()
    
    // 连接不活动时的最大生存时间
    sqlDB.SetConnMaxIdleTime(time.Second * 30)
    sqlDB.SetConnMaxLifetime(config.New(typeName).GetDuration("ConnMaxLifetime") * time.Second)
    
    MaxIdleConns := config.New(typeName).GetInt("MaxIdleConns")
    MaxOpenConns := config.New(typeName).GetInt("MaxOpenConns")

    // 连接超时相关
    sqlDB.SetMaxIdleConns(MaxIdleConns)
    sqlDB.SetMaxOpenConns(MaxOpenConns)
    
    if config.GetDatabaseConfig().GetString("Debug") == "dev" {
        db = db.Debug()
    }
    
    return db
}

func CloseDb()  {
    if sqlDB.Ping() != nil {
        return
    }
    sqlDB.Close()
}

/**
 * 连接 DSN
 */
func GetMysqlDSN(typeName string) string {
    Host := config.New(typeName).GetString("Host")
    Port := config.New(typeName).GetInt("Port")
    Username := config.New(typeName).GetString("Username")
    Password := config.New(typeName).GetString("Password")
    Charset := config.New(typeName).GetString("Charset")
    Database := config.New(typeName).GetString("Database")
    
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

