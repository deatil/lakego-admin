package ssh

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// Append one Error
func (this SSH) AppendError(err ...error) SSH {
    this.Errors = append(this.Errors, err...)

    return this
}

// return Error
func (this SSH) Error() error {
    return errors.Join(this.Errors...)
}
