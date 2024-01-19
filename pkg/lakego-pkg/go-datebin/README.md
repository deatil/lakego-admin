## go-datebin

### Desc

*  go-datebin is a simple datetime parse pkg.

[中文](README_CN.md) | English


### Download

~~~go
go get -u github.com/deatil/go-datebin
~~~


### Get Starting

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-datebin/datebin"
)

func main() {
    // now time
    date := datebin.
        Now().
        ToDatetimeString()
    // output: 2024-01-06 12:06:12

    // Parse date and have no timezone
    date2 := datebin.
        Parse("2032-03-15 12:06:17").
        ToDatetimeString(datebin.UTC)
    // output: 2032-03-15 12:06:17

    // Parse date and have timezone
    date2 := datebin.
        ParseWithLayout("2032-03-15 12:06:17", datebin.DatetimeFormat, datebin.GMT).
        ToDatetimeString()
    // output: 2032-03-15 12:06:17

    // set time and format output
    date3 := datebin.
        FromDatetime(2032, 3, 15, 12, 56, 5).
        ToFormatString("Y/m/d H:i:s")
    // output: 2032/03/15 12:56:05
}

~~~


### Examples

~~~go
// format timestamp
var datetimeString string = datebin.FromTimestamp(1705329727, datebin.Shanghai).ToDatetimeString()
// output: 2024-01-15 22:42:07
~~~

~~~go
// get now timestamp
var timestamp int64 = datebin.Now().Timestamp()
// output: 1705329727

// get now timestamp with timezone
var timestamp int64 = datebin.Now(datebin.UTC).Timestamp()
// output: 1705329757
~~~

~~~go
// get now stdtime
var stdTime time.Time = datebin.Now().ToStdTime()
// fmt.Sprintf("%s", stdTime) output: 2024-01-15 23:55:03.0770405 +0800 CST

// get now stdtime with timezone
var stdTime time.Time = datebin.Now(datebin.UTC).ToStdTime()
// fmt.Sprintf("%s", stdTime) output: 2024-01-19 01:59:11.8134897 +0000 UTC
~~~

~~~go
// format stdtime
var datetimeString string = datebin.FromStdTime(stdTime).ToDatetimeString()
// output: 2024-01-15 23:55:03
~~~

~~~go
// format datetime
var datetimeString string = datebin.FromDatetime(2024, 01, 15, 23, 35, 01).ToDatetimeString()
// output: 2024-01-15 23:35:01
~~~

more docs and see [docs](example.md)


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
