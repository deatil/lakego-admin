package cmd

import (
    "fmt"

    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/support/hash"
    authPassword "github.com/deatil/lakego-doak/lakego/auth/password"

    "github.com/deatil/lakego-doak-admin/admin/model"
)

/**
 * 重置密码
 *
 * > ./main lakego-admin:reset-password --id=[id] --password=[password]
 * > main.exe lakego-admin:reset-password --id=[id] --password=[password]
 * > go run main.go lakego-admin:reset-password --id=[id] --password=[password]
 *
 * @create 2021-9-26
 * @author deatil
 */
var ResetPasswordCmd = &command.Command{
    Use: "lakego-admin:reset-password",
    Short: "lakego-admin reset-password.",
    Example: "{execfile} lakego-admin:reset-password --id=[id] --password=[password]",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        ResetPassword()
    },
}

var id string
var password string

func init() {
    pf := ResetPasswordCmd.Flags()
    pf.StringVarP(&id, "id", "i", "", "账号ID")
    pf.StringVarP(&password, "password", "p", "", "新建密码")

    command.MarkFlagRequired(pf, "id")
    command.MarkFlagRequired(pf, "password")
}

// 重设权限
func ResetPassword() {
    if id == "" {
        fmt.Println("账号ID不能为空")
        return
    }

    if password == "" {
        fmt.Println("密码不能为空")
        return
    }

    password = hash.MD5(password)

    // 查询
    result := map[string]interface{}{}
    err := model.NewAdmin().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        fmt.Println("账号信息不存在")
        return
    }

    // 生成密码
    pass, encrypt := authPassword.MakePassword(password)

    err3 := model.NewAdmin().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "password": pass,
            "password_salt": encrypt,
        }).
        Error
    if err3 != nil {
        fmt.Println("修改密码失败")
        return
    }

    fmt.Println("修改密码成功")
}

