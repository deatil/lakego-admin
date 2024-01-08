package datebin

// 摩羯座
func (this Datebin) IsCapricornStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 12 && this.Day() >= 22 {
		return true
	}

	if this.Month() == 1 && this.Day() <= 19 {
		return true
	}

	return false
}

// 水瓶座
func (this Datebin) IsAquariusStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 1 && this.Day() >= 20 {
		return true
	}

	if this.Month() == 2 && this.Day() <= 18 {
		return true
	}

	return false
}

// 双鱼座
func (this Datebin) IsPiscesStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 2 && this.Day() >= 19 {
		return true
	}

	if this.Month() == 3 && this.Day() <= 20 {
		return true
	}

	return false
}

// 白羊座
func (this Datebin) IsAriesStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 3 && this.Day() >= 21 {
		return true
	}

	if this.Month() == 4 && this.Day() <= 20 {
		return true
	}

	return false
}

// 金牛座
func (this Datebin) IsTaurusStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 4 && this.Day() >= 21 {
		return true
	}

	if this.Month() == 5 && this.Day() <= 20 {
		return true
	}

	return false
}

// 双子座
func (this Datebin) IsGeminiStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 5 && this.Day() >= 21 {
		return true
	}

	if this.Month() == 6 && this.Day() <= 21 {
		return true
	}

	return false
}

// 巨蟹座
func (this Datebin) IsCancerStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 6 && this.Day() >= 22 {
		return true
	}

	if this.Month() == 7 && this.Day() <= 22 {
		return true
	}

	return false
}

// 狮子座
func (this Datebin) IsLeoStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 7 && this.Day() >= 23 {
		return true
	}

	if this.Month() == 8 && this.Day() <= 22 {
		return true
	}
	return false
}

// 处女座
func (this Datebin) IsVirgoStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 8 && this.Day() >= 23 {
		return true
	}

	if this.Month() == 9 && this.Day() <= 22 {
		return true
	}
	return false
}

// 天秤座
func (this Datebin) IsLibraStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 9 && this.Day() >= 23 {
		return true
	}

	if this.Month() == 10 && this.Day() <= 23 {
		return true
	}

	return false
}

// 天蝎座
func (this Datebin) IsScorpioStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 10 && this.Day() >= 24 {
		return true
	}

	if this.Month() == 11 && this.Day() <= 21 {
		return true
	}

	return false
}

// 射手座
func (this Datebin) IsSagittariusStar() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 11 && this.Day() >= 22 {
		return true
	}

	if this.Month() == 12 && this.Day() <= 21 {
		return true
	}

	return false
}
