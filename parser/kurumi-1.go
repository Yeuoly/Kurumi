package parser

type KurumiParserV1 struct {
	key string
	ParserInterface
}

func (p KurumiParserV1) Encrypt(src []uint8) []uint8 {
	key_bytes := make([]uint8, len(p.key))
	for i := 0; i < len(p.key); i++ {
		key_bytes[i] = uint8(p.key[i])
	}

	//16 rounds to generate subkey
	subkeys := make([][8]uint8, 16)
	for i := 0; i < 16; i++ {
		for j := 0; j < 8; j++ {
			subkeys[i][j] = key_bytes[(i*8+j)%len(p.key)]
		}
	}

	//split src into 8 bytes blocks
	blocks := make([][8]uint8, len(src)/8)
	for i := 0; i < len(src)/8; i++ {
		for j := 0; j < 8; j++ {
			blocks[i][j] = src[i*8+j]
		}
	}

	//encrypt
	for i := 0; i < len(blocks); i++ {
		for j := 0; j < 16; j++ {
			for k := 0; k < 8; k++ {
				blocks[i][k] ^= subkeys[j][k]
			}
		}
	}

	return src
}

func (p KurumiParserV1) DecryptSourceCode() []uint8 {
	return []uint8(``)
}

func GetKurumiParserV1(key string) KurumiParserV1 {
	return KurumiParserV1{key: key}
}
