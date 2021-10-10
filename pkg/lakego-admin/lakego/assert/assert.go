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

