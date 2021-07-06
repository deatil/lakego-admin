package container

import (
	"strings"
	"sync"
)

var sMap sync.Map

// 实例化
func New() *containers {
	return &containers{}
}

/**
 * 容器结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type containers struct {
}

// 键值对的形式将代码注册到容器
func (c *containers) Set(key string, value interface{}) bool {
	// 存在则删除旧的
	if _, exists := c.KeyIsExists(key); exists {
		sMap.Delete(key)
	}
	
	sMap.Store(key, value)
	
	return true
}

/**
 * 设置一个key的值为数组
 */
func (c *containers) SetItems(key string, value interface{}) bool {
	var newValues []interface{}
	
	if newValue, exists := c.KeyIsExists(key); exists {
		// 强制转换为 []interface{} 后增加数据
		newValues = append(newValue.([]interface{}), value)
	} else {
		newValues = append(newValues, value)
	}
	
	sMap.Store(key, newValues)
	
	return true
}

// 删除
func (c *containers) Delete(key string) {
	sMap.Delete(key)
}

// 从容器获取值
func (c *containers) Get(key string) interface{} {
	if value, exists := c.KeyIsExists(key); exists {
		return value
	}
	return nil
}

// 判断键是否被注册
func (c *containers) KeyIsExists(key string) (interface{}, bool) {
	return sMap.Load(key)
}

// 按照键的前缀模糊删除容器中注册的内容
func (c *containers) FuzzyDelete(keyPre string) {
	sMap.Range(func(key, value interface{}) bool {
		if keyname, ok := key.(string); ok {
			if strings.HasPrefix(keyname, keyPre) {
				sMap.Delete(keyname)
			}
		}
		return true
	})
}
