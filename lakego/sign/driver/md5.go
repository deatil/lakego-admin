package driver

import (
    "strings"

    "lakego-admin/lakego/sign/crypt"
)

type MD5 struct {
}

// 初始化
func (m *MD5) Init(conf map[string]interface{}) {
}

// 签名
func (m *MD5) Sign(data string) string {
    return strings.ToUpper(crypt.MD5(data))
}

// 验证
func (m *MD5) Validate(data string, signData string) bool {
    newData := m.Sign(data)

    return newData == signData
}
