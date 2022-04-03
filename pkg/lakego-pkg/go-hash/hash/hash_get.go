package hash

// 数据
func (this Hash) GetData() [][]byte {
    return this.data
}

// Hash 后的数据
func (this Hash) GetHashedData() string {
    return this.hashedData
}

// 错误信息
func (this Hash) GetError() error {
    return this.Error
}
