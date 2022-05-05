package interfaces

/**
 * 日志驱动接口
 *
 * @create 2021-11-3
 * @author deatil
 */
type Driver interface {
    // 自定义数据
    WithField(string, any) any

    // 自定义数据
    WithFields(map[string]any) any

    // ======

    Trace(...any)

    Debug(...any)

    Info(...any)

    Warn(...any)

    Warning(...any)

    Error(...any)

    Fatal(...any)

    Panic(...any)

    // ======

    Tracef(string, ...any)

    Debugf(string, ...any)

    Infof(string, ...any)

    Warnf(string, ...any)

    Warningf(string, ...any)

    Errorf(string, ...any)

    Fatalf(string, ...any)

    Panicf(string, ...any)
}
