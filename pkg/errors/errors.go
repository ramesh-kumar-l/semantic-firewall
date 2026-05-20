package errors

import "fmt"

type Code string

const (
	CodeInvalidInput   Code = "INVALID_INPUT"
	CodePromptTooLarge Code = "PROMPT_TOO_LARGE"
	CodeInternalError  Code = "INTERNAL_ERROR"
	CodePolicyDeny     Code = "POLICY_DENY"
	CodeTimeout        Code = "TIMEOUT"
)

type FirewallError struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Cause   error  `json:"-"`
}

func (e *FirewallError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *FirewallError) Unwrap() error {
	return e.Cause
}

func New(code Code, message string) *FirewallError {
	return &FirewallError{Code: code, Message: message}
}

func Wrap(code Code, message string, cause error) *FirewallError {
	return &FirewallError{Code: code, Message: message, Cause: cause}
}
