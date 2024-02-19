package datebin

// 摩羯座
// if the time is Capricorn Star ?
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
// if the time is Aquarius Star ?
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
// if the time is Pisces Star ?
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
// if the time is Aries Star ?
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
// if the time is Taurus Star ?
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
// if the time is Gemini Star ?
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
// if the time is Cancer Star ?
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
// if the time is Leo Star ?
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
// if the time is Virgo Star ?
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
// if the time is Libra Star ?
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
// if the time is Scorpio Star ?
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
// if the time is Sagittarius Star ?
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
