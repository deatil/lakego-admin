package cmd

import (
    "fmt"

    "github.com/deatil/lakego-doak/lakego/command"

    "github.com/deatil/lakego-doak-admin/admin/model"
    "github.com/deatil/lakego-doak-admin/admin/support/utils"
    auth_password "github.com/deatil/lakego-doak-admin/admin/password"
)

/**
 * 重置账号密码
 *
 * > ./main lakego-admin:reset-password --name=[name] --password=[password]
 * > main.exe lakego-admin:reset-password --name=[name] --password=[password]
 * > go run main.go lakego-admin:reset-password --name=[name] --password=[password]
 *
 * > go run main.go lakego-admin:reset-password --name=admin --password=123456
 *
 * @create 2021-9-26
 * @author deatil
 */
var ResetPasswordCmd = &command.Command{
    Use: "lakego-admin:reset-password",
    Short: "lakego-admin reset-password.",
    Example: "{execfile} lakego-admin:reset-password --name=[name] --password=[password]",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        ResetPassword()
    },
}

var userName string
var password string

func init() {
    pf := ResetPasswordCmd.Flags()
    pf.StringVarP(&userName, "name", "n", "", "账号")
    pf.StringVarP(&password, "password", "p", "", "新建密码")

    command.MarkFlagRequired(pf, "name")
    command.MarkFlagRequired(pf, "password")
}

// 重设权限
func ResetPassword() {
    if userName == "" {
        fmt.Println("账号不能为空")
        return
    }

    if password == "" {
        fmt.Println("密码不能为空")
        return
    }

    password = utils.MD5(password)

    // 查询
    result := map[string]any{}
    err := model.NewAdmin().
        Where("name = ?", userName).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        fmt.Println("账号信息不存在")
        return
    }

    // 生成密码
    pass, encrypt := auth_password.MakePassword(password)

    err3 := model.NewAdmin().
        Where("name = ?", userName).
        Updates(map[string]any{
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

