package config

import (
	"lakego-admin/lakego/config"
	"lakego-admin/lakego/config/interfaces"
)

/**
 * 配置
 *
 * @create 2021-6-20
 * @author deatil
 */
func New(name string) interfaces.ConfigInterface {
	conf := config.NewConfig(name)
	return conf
}

