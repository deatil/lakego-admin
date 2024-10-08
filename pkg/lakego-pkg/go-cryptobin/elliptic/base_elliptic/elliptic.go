// Package `base_elliptic` implements Elliptic curves over binary fields
package base_elliptic

// Create new elliptic curves over binary fields
// warning: params dose not validated.
//
// `base_elliptic` uses `ellipse.CurveParams` for compatibility with `crypto.ellipse` package.
// But do not use the functions of `ellipse.CurveParams`. It will be panic.
func NewCurve(params *CurveParams) Curve {
    return &curve{
        params: params,
    }
}
