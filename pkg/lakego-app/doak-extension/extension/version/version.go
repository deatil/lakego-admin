package version

import (
    "errors"
    "github.com/Masterminds/semver/v3"
)

var (
    NewConstraint = semver.NewConstraint
    NewVersion    = semver.NewVersion
)

// 版本检测
func VersionCheck(version string, constraint string) error {
    c, err := semver.NewConstraint(constraint)
    if err != nil {
        return err
    }

    v, err := semver.NewVersion(version)
    if err != nil {
        return err
    }

    if !c.Check(v) {
        return errors.New("version error")
    }

    return nil
}
