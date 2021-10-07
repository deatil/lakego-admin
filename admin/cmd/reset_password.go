package cmd

import (
    "fmt"

    "github.com/spf13/cobra"

    "lakego-admin/lakego/support/hash"
    authPassword "lakego-admin/lakego/auth/password"

    "lakego-admin/admin/model"
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
var ResetPasswordCmd = &cobra.Command{
    Use: "lakego-admin:reset-password",
    Short: "lakego-admin reset-password.",
    Example: "{execfile} lakego-admin:reset-password --id=[id] --password=[password]",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        ResetPassword()
    },
}

var id string
var password string

func init() {
    pf := ResetPasswordCmd.PersistentFlags()
    pf.StringVarP(&id, "id", "i", "", "账号ID")
    pf.StringVarP(&password, "password", "p", "", "新建密码")

    cobra.MarkFlagRequired(pf, "id")
    cobra.MarkFlagRequired(pf, "password")
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

