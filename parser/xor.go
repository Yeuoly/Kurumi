package parser

import "strconv"

type XorParser struct {
	ParserInterface
	key uint8
}

func xor(data []uint8, key uint8) []uint8 {
	for i := 0; i < len(data); i++ {
		data[i] ^= key
	}
	return data
}

func (p XorParser) Encrypt(src []uint8) []uint8 {
	return xor(src, p.key)
}

func (p XorParser) DecryptSourceCode() []uint8 {
	return []uint8(`
#include <stdint.h>
void de(uint8_t *data, uint32_t len, uint8_t *dst, uint32_t dstlen) {
	for (uint32_t i = 0; i < len; i++) {
		dst[i] = data[i] ^ ` + strconv.Itoa(int(p.key)) + `;
	}
}
	`)
}

func GetXorParser(key uint8) XorParser {
	return XorParser{key: key}
}
