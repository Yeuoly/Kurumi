package parser

type ParserInterface interface {
	/*
		Encrypt the source code
	*/
	Encrypt(src []uint8) []uint8
	/*
		DecryptSourceCode method requires bytes of c source code
		which contains a function has prototype like this:
		`void de(uint8_t *data, uint32_t len, uint8_t *dst, unit32_t dstlen);`
	*/
	DecryptSourceCode() []uint8
}
