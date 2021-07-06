package slice

func Contains(items []interface{}, item interface{}) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}

func ContainsInt(items []int, item int) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}

func ContainsInt64(items []int64, item int64) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}

func ContainsString(items []string, item string) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}
