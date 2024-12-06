package errors

// Join concatenates the elements of err to create a new error.
func Join(errs ...error) error {
    n := 0
    for _, err := range errs {
        if err != nil {
            n++
        }
    }

    if n == 0 {
        return nil
    }

    e := &Errors{
        errs: make([]error, 0, n),
    }

    for _, err := range errs {
        if err != nil {
            e.errs = append(e.errs, err)
        }
    }

    return e
}
