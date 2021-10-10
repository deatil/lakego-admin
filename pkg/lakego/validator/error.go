package validator

// DefaultCode default parameter error code
var DefaultCode = 400

// Error error struct
type Error struct {
    Message       string
    Code          int
    CustomMessage string
}

// NewError returns the instance of Error
func NewError(message string, code int, customMessage string) Error {
    return Error{
        Message:       message,
        Code:          code,
        CustomMessage: customMessage,
    }
}
