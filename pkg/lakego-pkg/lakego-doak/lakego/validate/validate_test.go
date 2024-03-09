package validate

import (
    "testing"
)

func Test_ValidateMapError(t *testing.T) {
    // 规则
    rules := map[string]any{
        "parentid": "required",
        "title": "required,max=50",
        "status": "required",
    }

    // 错误提示
    messages := map[string]string{
        "parentid.required": "parentid not empty",
        "title.required": "title not empty",
        "title.max": "title max 50 len",
        "status.required": "status not empty",
    }

    data := map[string]any{
        "title": "title",
        "status": 1,
    }

    ok, err := ValidateMapError(data, rules, messages)
    if ok {
        t.Error("should not ok")
    }

    if err == "" {
        t.Error("should throw error")
    }

    check := "parentid not empty"
    if err != check {
        t.Errorf("err return fail, got %s, want %s", err, check)
    }
}

func Test_ValidateError(t *testing.T) {
    data := struct{
        Parentid int    `json:"parentid" validate:"required"`
        Title    string `json:"title" validate:"required,max=50"`
        Email    int    `json:"email" validate:"required"`
        Status   int    `json:"status" validate:"required"`
    }{
        Parentid: 1,
        Title: "title",
        Status: 1,
    }

    // 错误提示
    messages := map[string]string{
        "Parentid.required": "parentid not empty",
        "Title.required":    "title not empty",
        "Title.max":         "title max 50 len",
        "Email.required":    "email not empty",
        "Status.required":   "status not empty",
    }

    ok, err := ValidateError(data, messages)
    if ok {
        t.Error("should not ok")
    }

    if err == "" {
        t.Error("should throw error")
    }

    check := "email not empty"
    if err != check {
        t.Errorf("err return fail, got %s, want %s", err, check)
    }

    // =========

    ok2, err2 := Validate(data, messages)
    if ok2 {
        t.Error("should not ok")
    }

    if err2.Len() == 0 {
        t.Error("should throw error")
    }

    check2 := "email not empty"
    if err2.Data("Email.required") != check2 {
        t.Errorf("err return fail, got %s, want %s", err, check)
    }

    if err2.Data("Status.required") != "" {
        t.Error("Status required should empty")
    }
}
