package redis

import (
	"lakego-admin/lakego/config"
	"lakego-admin/lakego/redis"
)

/**
 * redis
 *
 * @create 2021-6-20
 * @author deatil
 */
func New() redis.Redis {
	conf := config.NewConfig("redis")
	
	db := conf.GetInt("DB")
	addr := conf.GetString("Host")
	password := conf.GetString("Password")
	keyPrefix := conf.GetString("KeyPrefix")
	
	return redis.New(redis.Config{
		DB: db,
		Host: addr,
		Password: password,
		KeyPrefix: keyPrefix,
	})
}

/**
 * redis，带 DB 选择
 *
 * @create 2021-6-20
 * @author deatil
 */
func NewWithDB(mainDB int) redis.Redis {
	conf := config.NewConfig("redis")
	
	addr := conf.GetString("Host")
	password := conf.GetString("Password")
	keyPrefix := conf.GetString("KeyPrefix")
	
	return redis.New(redis.Config{
		DB: mainDB,
		Host: addr,
		Password: password,
		KeyPrefix: keyPrefix,
	})
}

