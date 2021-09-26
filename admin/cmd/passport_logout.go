package cmd

import (
    "fmt"

    "github.com/spf13/cobra"

    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/support/time"
    "lakego-admin/lakego/facade/auth"
    "lakego-admin/lakego/facade/cache"

    "lakego-admin/admin/model"
)

/**
 * 强制将 jwt 的 refreshToken 放入黑名单
 *
 * > ./main lakego-admin:passport-logout
 * > main.exe lakego-admin:passport-logout
 * > go run main.go lakego-admin:passport-logout
 *
 * @create 2021-9-26
 * @author deatil
 */
var PassportLogoutCmd = &cobra.Command{
    Use: "lakego-admin:passport-logout",
    Short: "lakego-admin passport-logout.",
    Example: "{execfile} lakego-admin:passport-logout",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        PassportLogout()
    },
}

var refreshToken string

func init() {
    pf := ResetPaswordCmd.PersistentFlags()
    pf.StringVarP(&refreshToken, "refreshToken", "r", "", "刷新token")

    cobra.MarkFlagRequired(pf, "refreshToken")
}

// 强制将 jwt 的 refreshToken 放入黑名单
func PassportLogout() {
    c := cache.New()

    if c.Has(hash.MD5(refreshToken)) {
        fmt.Println("refreshToken已失效")
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

    c.Put(hash.MD5(refreshToken), "no", int64(refreshTokenExpiresIn))

    model.NewAdmin().
        Where("id = ?", refreshAdminid).
        Updates(map[string]interface{}{
            "refresh_time": time.NowTimeToInt(),
            "refresh_ip": "",
        })

    fmt.Println("账号退出成功")
}

