## go-datebin

### Desc

*  go-datebin is simple datetime parse pkg.

[中文](README.md) | English


### Download

~~~go
go get -u github.com/deatil/go-datebin
~~~


### Use

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
    // output: 2024-1-6 12:06:12

    // Parse date and have no timezone
    date2 := datebin.
        Parse("2032-03-15 12:06:17").
        ToDatetimeString(datebin.UTC)
    // output: 2032-3-15 12:06:17

    // Parse date and have timezone
    date2 := datebin.
        ParseWithLayout("2032-03-15 12:06:17", datebin.DatetimeFormat, datebin.GMT).
        ToDatetimeString()
    // output: 2032-3-15 12:06:17

    // set time and format output
    date3 := datebin.
        FromDatetime(2032, 3, 15, 12, 56, 5).
        ToFormatString("Y/m/d H:i:s")
    // output: 2032/3/15 12:56:05
}

~~~

more docs and see [docs](example.md)


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
