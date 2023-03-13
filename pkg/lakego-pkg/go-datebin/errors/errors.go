package errors

func New(errs ...error) error {
    n := 0
    for _, err := range errs {
        if err != nil {
            n++
        }
    }

    if n == 0 {
        return nil
    }

    e := &errors{
        errs: make([]error, 0, n),
    }

    for _, err := range errs {
        if err != nil {
            e.errs = append(e.errs, err)
        }
    }

    return e
}

type errors struct {
    errs []error
}

func (e *errors) Error() string {
    var b []byte

    for i, err := range e.errs {
        if i > 0 {
            b = append(b, '\n')
        }
        b = append(b, err.Error()...)
    }

    return string(b)
}

func (e *errors) Unwrap() []error {
    return e.errs
}
