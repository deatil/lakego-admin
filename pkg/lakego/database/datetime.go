package database

import (
    "fmt"
    "time"
    "strings"
    "encoding/json"
    "database/sql"
    "database/sql/driver"
)

var timeFormat = "2006-01-02 15:04:05"

// custom time types
// Used to format time into a human-readable string
type Datetime sql.NullTime

// Scan implements the Scanner interface.
func (a *Datetime) Scan(value interface{}) error {
    return (*sql.NullTime)(a).Scan(value)
}

// Value implements the driver Valuer interface.
func (a Datetime) Value() (driver.Value, error) {
    if !a.Valid {
        return nil, nil
    }

    return a.Time.Format(timeFormat), nil
}

func (a Datetime) MarshalJSON() ([]byte, error) {
    if a.Valid {
        return []byte(fmt.Sprintf("\"%s\"", a.Time.Format(timeFormat))), nil
    }

    return json.Marshal(nil)
}

func (a *Datetime) UnmarshalJSON(b []byte) error {
    s := strings.Trim(string(b), "\"")

    if s == "null" || s == "" {
        a.Valid = false
        a.Time = time.Time{}
        return nil
    }

    cst, err := time.LoadLocation("Asia/Shanghai")
    if err != nil {
        return fmt.Errorf("time.LoadLocation error: %s", err.Error())
    }

    a.Time, err = time.ParseInLocation(timeFormat, s, cst)
    if err != nil {
        // When time cannot be resolved using the default format, try RFC3339Nano
        if a.Time, err = time.ParseInLocation(time.RFC3339Nano, s, cst); err == nil {
            a.Time = a.Time.In(cst)
        }
    }

    a.Valid = true
    return err
}
