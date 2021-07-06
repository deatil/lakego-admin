package redis

import (
	"context"
	"fmt"
	"time"
	"errors"
	
	"github.com/go-redis/cache/v8"
	"github.com/go-redis/redis/v8"
	
	"lakego-admin/lakego/logger"
)

type Config struct {
	DB int
	Host string
	Password string
	KeyPrefix string
}

type Redis struct {
	cache  *cache.Cache
	client *redis.Client
	prefix string
	config Config
}

// NewRedis creates a new redis client instance
func New(config Config) Redis {
	mainDB := config.DB
	addr := config.Host
	password := config.Password
	keyPrefix := config.KeyPrefix

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		DB:       mainDB,
		Password: password,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.Ping(ctx).Result(); err != nil {
		logger.Error(err.Error())
	}

	return Redis{
		client: client,
		prefix: keyPrefix,
		cache: cache.New(&cache.Options{
			Redis:      client,
			LocalCache: cache.NewTinyLFU(1000, time.Minute),
		}),
	}
}

func (a Redis) wrapperKey(key string) string {
	return fmt.Sprintf("%s:%s", a.prefix, key)
}

// int 时间格式化为 Duration 格式
func (a Redis) IntTimeToDuration(t int) time.Duration {
	return time.Duration(int64(t))
}

// 设置
func (a Redis) Set(key string, value interface{}, expiration int) error {
	ttl := a.IntTimeToDuration(expiration)
	
	return a.cache.Set(&cache.Item{
		Ctx:            context.TODO(),
		Key:            a.wrapperKey(key),
		Value:          value,
		TTL:            ttl,
		SkipLocalCache: true,
	})
}

// 获取
func (a Redis) Get(key string, value interface{}) error {
	err := a.cache.Get(context.TODO(), a.wrapperKey(key), value)
	if err == cache.ErrCacheMiss {
		err = errors.New("Redis Key No Exist")
	}

	return err
}

func (a Redis) Delete(keys ...string) (bool, error) {
	wrapperKeys := make([]string, len(keys))
	for index, key := range keys {
		wrapperKeys[index] = a.wrapperKey(key)
	}

	cmd := a.client.Del(context.TODO(), wrapperKeys...)
	if err := cmd.Err(); err != nil {
		return false, err
	}

	return cmd.Val() > 0, nil
}

func (a Redis) Check(keys ...string) (bool, error) {
	wrapperKeys := make([]string, len(keys))
	for index, key := range keys {
		wrapperKeys[index] = a.wrapperKey(key)
	}

	cmd := a.client.Exists(context.TODO(), wrapperKeys...)
	if err := cmd.Err(); err != nil {
		return false, err
	}
	return cmd.Val() > 0, nil
}

func (a Redis) Close() error {
	return a.client.Close()
}

func (a Redis) GetClient() *redis.Client {
	return a.client
}
