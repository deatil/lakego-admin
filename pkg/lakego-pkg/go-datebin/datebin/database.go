package datebin

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// 实现 sql.Scanner 接口，Scan 将 value 填充进结构体
// sql.Scanner interface
func (this *Datebin) Scan(value any) error {
	data, ok := value.(time.Time)
	if ok {
		*this = Datebin{time: data, loc: time.Local}

		return nil
	}

	return fmt.Errorf("data type err: %v", value)
}

// 实现 driver.Valuer 接口，Value 返回数据
// driver.Valuer interface
func (this Datebin) Value() (driver.Value, error) {
	if this.IsZero() {
		return nil, nil
	}

	return this.time, nil
}
