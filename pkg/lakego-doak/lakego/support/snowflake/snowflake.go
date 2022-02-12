package snowflake

import (
    "sync"
    "time"
    "errors"
)

/*×
 * 雪花算法
 *
 * 1                                               42           52             64
 * +-----------------------------------------------+------------+---------------+
 * | timestamp(ms)                                 | workerid   | sequence      |
 * +-----------------------------------------------+------------+---------------+
 * | 0000000000 0000000000 0000000000 0000000000 0 | 0000000000 | 0000000000 00 |
 * +-----------------------------------------------+------------+---------------+
 *
 * 1. 41位时间截(毫秒级)，注意这是时间截的差值（当前时间截 - 开始时间截)。可以使用约70年: (1L << 41) / (1000L * 60 * 60 * 24 * 365) = 69
 * 2. 10位数据机器位，可以部署在1024个节点
 * 3. 12位序列，毫秒内的计数，同一机器，同一时间截并发4096个序号
 */

// 生产雪花 ID
func Make(workerid int64) (int64, error) {
    snowflake, err := New(workerid)
    if err != nil {
        return nil, err
    }

    id := snowflake.Generate()

    return id, nil
}

// 构造函数
func New(workerid int64) (*Snowflake, error) {
    if workerid < 0 || workerid > workeridMax {
        return nil, errors.New("工作ID(workerid)必须在 0 和 1023 之间")
    }

    return &Snowflake{
        timestamp: 0,
        workerid:  workerid,
        sequence:  0,
    }, nil
}

const (
    twepoch        = int64(1483228800000)             // 开始时间截 (2017-01-01)
    workeridBits   = uint(10)                         // 机器id所占的位数
    sequenceBits   = uint(12)                         // 序列所占的位数
    workeridMax    = int64(-1 ^ (-1 << workeridBits)) // 支持的最大机器id数量
    sequenceMask   = int64(-1 ^ (-1 << sequenceBits)) // 机器ID
    workeridShift  = sequenceBits                     // 机器id左移位数
    timestampShift = sequenceBits + workeridBits      // 时间戳左移位数
)

/**
 * 雪花算法
 *
 * @create 2022-2-12
 * @author deatil
 */
type Snowflake struct {
    sync.Mutex

    workerid  int64
    sequence  int64
    timestamp int64
}

// 生产雪花 ID
func (this *Snowflake) Generate() int64 {
    this.Lock()

    now := time.Now().UnixNano() / 1000000

    if this.timestamp == now {
        this.sequence = (this.sequence + 1) & sequenceMask

        if this.sequence == 0 {
            for now <= this.timestamp {
                now = time.Now().UnixNano() / 1000000
            }
        }
    } else {
        this.sequence = 0
    }

    this.timestamp = now

    r := int64((now-twepoch) << timestampShift | (this.workerid << workeridShift) | (this.sequence))

    this.Unlock()
    return r
}
