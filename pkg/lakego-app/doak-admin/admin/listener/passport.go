package listener

import (
    "github.com/deatil/lakego-doak/lakego/facade"
)

// 登录统一日志记录
type PassportLoginError struct{}

func (this *PassportLoginError) Handle(err string) {
    facade.Logger.Error("[login]" + err)
}
