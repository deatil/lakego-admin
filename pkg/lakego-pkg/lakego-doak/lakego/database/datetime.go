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
func (this *Datetime) Scan(value any) error {
    return (*sql.NullTime)(this).Scan(value)
}

// Value implements the driver Valuer interface.
func (this Datetime) Value() (driver.Value, error) {
    if !this.Valid {
        return nil, nil
    }

    return this.Time.Format(timeFormat), nil
}

func (this Datetime) MarshalJSON() ([]byte, error) {
    if this.Valid {
        return []byte(fmt.Sprintf("\"%s\"", this.Time.Format(timeFormat))), nil
    }

    return json.Marshal(nil)
}

func (this *Datetime) UnmarshalJSON(b []byte) error {
    s := strings.Trim(string(b), "\"")

    if s == "null" || s == "" {
        this.Valid = false
        this.Time = time.Time{}
        return nil
    }

    cst, err := time.LoadLocation("Asia/Shanghai")
    if err != nil {
        return fmt.Errorf("time.LoadLocation error: %s", err.Error())
    }

    this.Time, err = time.ParseInLocation(timeFormat, s, cst)
    if err != nil {
        // When time cannot be resolved using the default format, try RFC3339Nano
        if this.Time, err = time.ParseInLocation(time.RFC3339Nano, s, cst); err == nil {
            this.Time = this.Time.In(cst)
        }
    }

    this.Valid = true
    return err
}
