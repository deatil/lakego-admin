package config

import (
	"time"
	
	"lakego-admin/lakego/config"
	"lakego-admin/lakego/config/interfaces"
)

type Config struct {
	typeName string
}

/**
 * 连接类型
 */
func GetDatabaseConfig() interfaces.ConfigInterface {
	databaseConfig := config.New("database")
	
	return databaseConfig
}

/**
 * 连接类型
 */
func GetConnectionType() string {
	typeName := GetDatabaseConfig().GetString("Default")
	
	return typeName
}

func New(typeName string) *Config {
	return &Config{
		typeName,
	}
}

func (c *Config) GetConnectionString(keyName string) (s string) {
	s = "connections." + c.typeName + "." + keyName
	return
}

func (c *Config) GetInt(keyName string) (i int) {
	keyString := c.GetConnectionString(keyName)
	i = GetDatabaseConfig().GetInt(keyString)
	return
}

func (c *Config) GetDuration(keyName string) (d time.Duration) {
	keyString := c.GetConnectionString(keyName)
	d = GetDatabaseConfig().GetDuration(keyString)
	return
}

func (c *Config) GetString(keyName string) (s string) {
	keyString := c.GetConnectionString(keyName)
	s = GetDatabaseConfig().GetString(keyString)
	return
}
