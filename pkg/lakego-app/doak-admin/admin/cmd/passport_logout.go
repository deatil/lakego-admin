package cmd

import (
    "fmt"

    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade/cache"

    "github.com/deatil/lakego-doak-admin/admin/model"
    "github.com/deatil/lakego-doak-admin/admin/auth/auth"
    "github.com/deatil/lakego-doak-admin/admin/support/utils"
)

/**
 * 强制将 jwt 的 refreshToken 放入黑名单
 *
 * > ./main lakego-admin:passport-logout --refreshToken=[token]
 * > main.exe lakego-admin:passport-logout --refreshToken=[token]
 * > go run main.go lakego-admin:passport-logout --refreshToken=[token]
 *
 * @create 2021-9-26
 * @author deatil
 */
var PassportLogoutCmd = &command.Command{
    Use: "lakego-admin:passport-logout",
    Short: "lakego-admin passport-logout.",
    Example: "{execfile} lakego-admin:passport-logout",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        PassportLogout()
    },
}

var refreshToken string

func init() {
    // 全局
    // pf := PassportLogoutCmd.PersistentFlags()

    // 当前命令
    pf := PassportLogoutCmd.Flags()
    pf.StringVarP(&refreshToken, "refreshToken", "r", "", "刷新token")

    command.MarkFlagRequired(pf, "refreshToken")
}

// 强制将 jwt 的 refreshToken 放入黑名单
func PassportLogout() {
    c := cache.New()

    if c.Has(utils.MD5(refreshToken)) {
        fmt.Println("refreshToken 已失效")
        return
    }

    // jwt
    jwter := auth.New()

    // 拿取数据
    claims, claimsErr := jwter.GetRefreshTokenClaims(refreshToken, false)
    if claimsErr != nil {
        fmt.Println("refreshToken 已失效")
        return
    }

    // 当前账号ID
    refreshAdminid := jwter.GetDataFromTokenClaims(claims, "id")

    // 过期时间
    exp := jwter.GetFromTokenClaims(claims, "exp")
    iat := jwter.GetFromTokenClaims(claims, "iat")
    refreshTokenExpiresIn := exp.(float64) - iat.(float64)

    c.Put(utils.MD5(refreshToken), "no", int64(refreshTokenExpiresIn))

    model.NewAdmin().
        Where("id = ?", refreshAdminid).
        Updates(map[string]any{
            "refresh_time": int(datebin.NowTimestamp()),
            "refresh_ip": "127.0.0.1",
        })

    fmt.Println("账号退出成功")
}

