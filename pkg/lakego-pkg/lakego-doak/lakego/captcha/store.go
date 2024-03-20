package captcha

import (
    "errors"
)

/**
 * 空存储
 *
 * @create 2021-10-18
 * @author deatil
 */
type EmptyStore struct {}

// 设置
func (this *EmptyStore) Set(id string, value string) error {
    return errors.New("接口未定义")
}

// 获取
func (this *EmptyStore) Get(id string, clear bool) string {
    return ""
}

// 验证
func (this *EmptyStore) Verify(id string, answer string, clear bool) bool {
    return false
}
