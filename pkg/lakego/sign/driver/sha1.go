package driver

import (
    "strings"

    "github.com/deatil/lakego-admin/lakego/sign/crypt"
)

type SHA1 struct {
}

// 初始化
func (s *SHA1) Init(conf map[string]interface{}) {
}

// 签名
func (s *SHA1) Sign(data string) string {
    return strings.ToUpper(crypt.SHA1(data))
}

// 验证
func (s *SHA1) Validate(data string, signData string) bool {
    newData := s.Sign(data)

    return newData == signData
}
