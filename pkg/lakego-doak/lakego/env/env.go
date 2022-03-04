package env

import (
    "os"
    "errors"
    "strings"

    "github.com/joho/godotenv"
)

// 导入
// Load(filenames ...string) (err error)
var Load = godotenv.Load

// 覆盖导入
// Overload(filenames ...string) (err error)
var Overload = godotenv.Overload

// 读取
// Read(filenames ...string) (envMap map[string]string, err error)
var Read = godotenv.Read

// 解析
// Parse(r io.Reader) (envMap map[string]string, err error)
var Parse = godotenv.Parse

// 解析为 map
// Unmarshal(str string) (envMap map[string]string, err error)
var Unmarshal = godotenv.Unmarshal

var ToMap = godotenv.Unmarshal

// Exec(filenames []string, cmd string, cmdArgs []string) error
var Exec = godotenv.Exec

// 写入
// Write(envMap map[string]string, filename string) error
var Write = godotenv.Write

// 转为字符
// Marshal(envMap map[string]string) (string, error)
var Marshal = godotenv.Marshal

var ToEnvString = godotenv.Marshal

// 根据文件解析 env 数据
func ParseFile(path string) (map[string]string, error) {
    file, err := os.OpenFile(path, os.O_RDONLY, 0666)
    if err != nil {
        return map[string]string{}, err
    }

    return Parse(file)
}

// 根据文件解析 env 数据，并返回字符串
func ParseFileToString(path string) (string, error) {
    file, err := os.OpenFile(path, os.O_RDONLY, 0666)
    if err != nil {
        return "", err
    }

    // 解析
    env, err := Parse(file)
    if err != nil {
        return "", err
    }

    // 转为字符串
    contents, err := Marshal(env)
    if err != nil {
        return "", err
    }

    return contents, nil
}

// ==========

// 替换字符中的 ${var} or $var 为环境变量
func ExpandEnv(s string) string {
    return os.ExpandEnv(s)
}

// 获取环境变量
func Get(key string) string {
    return os.Getenv(key)
}

// 获取环境变量
func Lookup(key string) (string, bool) {
    return os.LookupEnv(key)
}

// 获取所有环境变量
// 每行结果：key=value
func Environ() []string {
    return os.Environ()
}

// 设置环境变量
func Set(setting string) error {
    s := strings.Split(setting, "=")

    if len(s) != 2 {
        return errors.New("setting: invalid")
    }

    return os.Setenv(s[0], s[1])
}

// 批量设置环境变量
func SetArray(settings []string) error {
    if len(settings) == 0 {
        return errors.New("setting: invalid")
    }

    for _, setting := range settings {
        s := strings.Split(setting, "=")

        if len(s) == 2 {
            os.Setenv(s[0], s[1])
        }
    }

    return nil
}

// 删除指定的环境变量
func Unset(key string) error {
    return os.Unsetenv(key)
}

// 清除所有环境变量
func Clear() {
    os.Clearenv()
}
