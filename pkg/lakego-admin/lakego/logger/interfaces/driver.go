package interfaces

/**
 * 日志驱动接口
 *
 * @create 2021-11-3
 * @author deatil
 */
type Driver interface {
    // 自定义数据
    WithField(string, interface{}) interface{}

    // 自定义数据
    WithFields(map[string]interface{}) interface{}

    // ======

    Trace(...interface{})

    Debug(...interface{})

    Info(...interface{})

    Warn(...interface{})

    Warning(...interface{})

    Error(...interface{})

    Fatal(...interface{})

    Panic(...interface{})

    // ======

    Tracef(string, ...interface{})

    Debugf(string, ...interface{})

    Infof(string, ...interface{})

    Warnf(string, ...interface{})

    Warningf(string, ...interface{})

    Errorf(string, ...interface{})

    Fatalf(string, ...interface{})

    Panicf(string, ...interface{})
}
