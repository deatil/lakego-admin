package errors

import (
	"github.com/pkg/errors"
)

// Alias
var (
	Is           = errors.Is
	As           = errors.As
	New          = errors.New
	Unwrap       = errors.Unwrap
	Wrap         = errors.Wrap
	Wrapf        = errors.Wrapf
	WithStack    = errors.WithStack
	WithMessage  = errors.WithMessage
	WithMessagef = errors.WithMessagef
)