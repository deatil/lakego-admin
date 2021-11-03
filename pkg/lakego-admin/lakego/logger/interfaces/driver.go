package interfaces

/**
 * 日志驱动接口
 *
 * @create 2021-11-3
 * @author deatil
 */
type Driver interface {
    Trace(...interface{})

    Tracef(string, ...interface{})

    Debug(...interface{})

    Debugf(string, ...interface{})

    Info(...interface{})

    Infof(string, ...interface{})

    Warn(...interface{})

    Warnf(string, ...interface{})

    Error(...interface{})

    Errorf(string, ...interface{})

    Fatal(...interface{})

    Fatalf(string, ...interface{})

    Panic(...interface{})

    Panicf(string, ...interface{})
}
