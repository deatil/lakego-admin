package cache

import (
	"lakego-admin/lakego/cache/driver/redis"
)

// 配置
type Config struct {
	Driver string
	Prefix string
	DriverConfig map[string]interface{}
}

// 缓存
type Cache struct {
	config Config
	driver CacheDriver
}

// 创建
func New(config Config) Cache {
	if config.Driver == "redis" {
		rdriver := createRedisDriver(config)
		
		return Cache{
			config: config,
			driver: rdriver,
		}
	} else {
		rdriver := createRedisDriver(config)
		
		return Cache{
			config: config,
			driver: rdriver,
		}
	}
}

// 创建 redis 驱动
func createRedisDriver(config Config) CacheDriver {
	conf := config.DriverConfig["redis"].(map[string]interface{})
	
	r := redis.New(redis.Config{
		DB: conf["db"].(int),
		Host: conf["host"].(string),
		Password: conf["password"].(string),
	})
	
	_ = r.SetPrefix(config.Prefix)
	
	return r
}

func (c Cache) Get(key string) (interface{}, error) {
	return c.driver.Get(key)
}

func (c Cache) Put(key string, value interface{}, seconds interface{}) error {
	return c.driver.Put(key, value, seconds)
}

func (c Cache) Forever(key string, value interface{}) error {
	return c.driver.Forever(key, value)
}

func (c Cache) Pull(key string) (interface{}, error) {
	var val interface{}
	var err error

	val, err = c.driver.Get(key)
	if err != nil {
		return val, err
	}

	c.driver.Forget(key)

	return val, nil
}

func (c Cache) Increment(key string, value ...int64) error {
	return c.driver.Increment(key, value...)
}

func (c Cache) Decrement(key string, value ...int64) error {
	return c.driver.Decrement(key, value...)
}

func (c Cache) Forget(key string) (bool, error) {
	return c.driver.Forget(key)
}

func (c Cache) Flush() (bool, error) {
	return c.driver.Flush()
}

func (c Cache) GetPrefix() string {
	return c.driver.GetPrefix()
}
