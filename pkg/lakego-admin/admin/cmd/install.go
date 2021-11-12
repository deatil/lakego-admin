package cmd

import (
    "os"
    "fmt"
    "strings"

    "github.com/deatil/lakego-admin/lakego/command"
    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/support/file"

    "github.com/deatil/lakego-admin/admin/model"
)

/**
 * 安装脚本
 *
 * > ./main lakego-admin:install
 * > main.exe lakego-admin:install
 * > go run main.go lakego-admin:install
 *
 * @create 2021-8-15
 * @author deatil
 */
var InstallCmd = &command.Command{
    Use: "lakego-admin:install",
    Short: "Install the lakego-admin.",
    Example: "{execfile} lakego-admin:install",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        // 运行安装
        runInsatll()
    },
}

// 运行安装
func runInsatll() {
    fmt.Println("开始安装并导入数据...")
    fmt.Println("")

    if ok := file.IsExist("./install.lock"); ok {
        fmt.Println("请先删除文件 [./install.lock] ！")
        os.Exit(1)
    }

    sqlFile := path.FormatPath("{root}/resources/database/lakego_admin.sql")
    dataExit := file.IsExist(sqlFile)
    if !dataExit {
        fmt.Println("数据库文件 [lakego_admin.sql] 不存在！")
        os.Exit(1)
    }

    sqls, _ := os.ReadFile(sqlFile)
    sqlArr := strings.Split(string(sqls), ";")
    for _, sql := range sqlArr {
        sql = strings.Trim(sql, " ")
        if sql == "" {
            continue
        }

        sql = strings.ToLower(sql)

        // 替换前缀
        prefix := model.GetConfig("prefix")
        sql = strings.ReplaceAll(sql, "pre__", prefix.(string))

        err := model.NewDB().Exec(sql).Error
        if err == nil {
            fmt.Println(sql, "\t 添加成功！")
        } else {
            fmt.Println(sql, err, "\t 添加失败！")
            os.Exit(1)
        }
    }

    installFile, _ := os.OpenFile("./install.lock", os.O_RDWR|os.O_CREATE, os.ModePerm)
    installFile.WriteString("")

    fmt.Println("")
    fmt.Println("安装成功。")
}
