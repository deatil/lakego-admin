package render

import (
    "strings"

    view_finder "github.com/deatil/lakego-doak/lakego/view/finder"
)

func hintPath(path string) (string, bool) {
    ok := false

    hintPathDelimiter := "::"
    if strings.Contains(path, hintPathDelimiter) {
        path = view_finder.Finder.Find(path)
        ok = true
    }

    return path, ok
}
