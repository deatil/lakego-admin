package trivium

func reverseInt8(value uint8) uint8 {
   value = ((value & 0xF0) >> 4) | ((value & 0x0F) << 4)
   value = ((value & 0xCC) >> 2) | ((value & 0x33) << 2)
   value = ((value & 0xAA) >> 1) | ((value & 0x55) << 1)

   return value;
}

func TRIVIUM_GET_BIT(s []uint8, n int) uint8 {
    return ((s[(n - 1) / 8] >> ((n - 1) % 8)) & 1)
}

//Set a given bit of the internal state
func TRIVIUM_SET_BIT(s []uint8, n int, v uint8) {
    s[(n - 1) / 8] = (s[(n - 1) / 8] & ^(1 << ((n - 1) % 8))) | (v << ((n - 1) % 8))
}
