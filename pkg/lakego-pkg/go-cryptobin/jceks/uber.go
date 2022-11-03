package jceks

const (
    UberVersionV1 = 1
)

/**
 * UBER
 *
 * @create 2022-9-19
 * @author deatil
 */
type UBER struct {
    BKS
}

// 构造函数
func NewUBER() *UBER {
    uber := &UBER{
        BKS{
            entries: make(map[string]any),
        },
    }

    return uber
}

// LoadUberFromBytes loads the key store from the bytes data.
func LoadUberFromBytes(data []byte, password string) (*UBER, error) {
    uber := &UBER{
        BKS{
            entries: make(map[string]any),
        },
    }

    err := uber.Parse(data, password)
    if err != nil {
        return nil, err
    }

    return uber, err
}

// 别名
var LoadUber      = LoadUberFromBytes
var NewUberEncode = NewUBER
