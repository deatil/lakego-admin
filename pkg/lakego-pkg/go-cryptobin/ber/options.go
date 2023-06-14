package ber

import (
    "fmt"
    "strconv"
    "strings"
)

type options struct {
    private     bool
    optional    bool
    application bool
    explicit    bool
    stringType  Tag
    timeType    Tag
    tag         *int
}

func newDefaultOptions() *options {
    return &options{
        stringType: TagUTF8String,
        timeType:   TagGeneralizedTime,
    }
}

func parseOptions(s string) (*options, error) {
    opts := newDefaultOptions()
    for _, token := range strings.Split(s, ",") {
        args := strings.Split(strings.TrimSpace(token), ":")
        err := parseOption(opts, args)
        if err != nil {
            return nil, err
        }
    }
    return opts, nil
}

func parseOption(opt *options, args []string) error {
    switch args[0] {
        // string types
        case "ia5":
            opt.stringType = TagIA5String
        case "printable":
            opt.stringType = TagPrintableString
        case "numeric":
            opt.stringType = TagNumericString
        case "utf8":
            opt.stringType = TagUTF8String
        // time types
        case "utc":
            opt.timeType = TagUTCTime
        // everything else
        case "private":
            opt.private = true
        case "optional":
            opt.optional = true
        case "application":
            opt.application = true
        case "tag":
            parseTagOption(opt, args)
        case "explicit":
            opt.explicit = true
    }

    return nil
}

func parseTagOption(opt *options, args []string) error {
    if len(args) != 2 {
        return fmt.Errorf("no value given for tag")
    }

    tag, err := strconv.Atoi(args[1])
    if err != nil {
        return fmt.Errorf("invalid tag value '%s'", args[1])
    }

    opt.tag = &tag
    return nil
}
