package assert

/**
 * 条件断言
 *
 * @create 2021-8-26
 * @author deatil
 */
func Assert(condition bool, message string) {
    if !condition {
        panic("Error#" + message)
    }
}

// 断言加默认返回
func AssertDefault(condition bool, def interface{}) interface{} {
    if !condition {
        return def
    }
}
