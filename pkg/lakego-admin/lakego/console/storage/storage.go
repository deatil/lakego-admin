package storage

import (
    "fmt"
    "strings"

    "github.com/deatil/lakego-admin/lakego/command"
    "github.com/deatil/lakego-admin/lakego/support/file"
    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/facade/config"
)

/**
 * 创建软连接
 *
 * > ./main lakego:storage-link [--force]
 * > main.exe lakego:storage-link [--force]
 * > go run main.go lakego:storage-link [--force]
 *
 * @create 2022-1-27
 * @author deatil
 */
var StorageLinkCmd = &command.Command{
    Use: "lakego:storage-link",
    Short: "创建公共资源软连接.",
    Example: "{execfile} lakego:storage-link",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {
    },
    Run: func(cmd *command.Command, args []string) {
        StorageLink()
    },
}

// 覆盖
var pForce bool

func init() {
    pf := StorageLinkCmd.Flags()
    pf.BoolVarP(&pForce, "force", "", false, "是否覆盖文件")
}

// 创建公共资源软连接
func StorageLink() {
    links := config.New("filesystem").GetStringSlice("Links")

    if len(links) > 0 {
        for _, link := range links {
            array := strings.Split(link, ":")
            if len(array) == 2 {
                from := path.FormatPath(array[1])
                to := path.FormatPath(array[0])

                if pForce {
                    file.Unlink(to)
                }

                file.Symlink(from, to)
            }
        }
    }

    fmt.Println("软连接创建成功")
}
