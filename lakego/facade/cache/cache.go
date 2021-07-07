package cache

import (
	"lakego-admin/lakego/config"
	"lakego-admin/lakego/cache"
)

/**
 * 缓存
 *
 * @create 2021-7-3
 * @author deatil
 */
func New() cache.Cache {
	conf := config.New("cache")
	
	driver := conf.GetString("Driver")
	prefix := conf.GetString("Prefix")
	driverConfig := conf.GetStringMap("Config")
	
	return cache.New(cache.Config{
		Driver: driver,
		Prefix: prefix,
		DriverConfig: driverConfig,
	})
}
