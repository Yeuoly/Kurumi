package parser

import (
	"strconv"
)

/*
Copyright (c) 2022, Kurumi Project, Default Inner Encryption Algorithms
All rights reserved.

Author: Kurumi Project/Yeuoly

This Algorithm is simple to understand and implement, it can partially protect the source code
from reverse engineering for free, it's useful when the attacker is a script kiddie.

There is two way to unshell the process, one is to use a debugger to break a point at execve
the other is write a script to decrypt

Anthor feature is that it can hide the harmful code to bypass the antivirus software
Cause the antivirus software has no feature of Kurumi, If has, KurimiParserVn will be
*/
type KurumiParserV2 struct {
	ParserInterface
	key uint64
}

func (p KurumiParserV2) Encrypt(src []uint8) []uint8 {
	/*
		struct Unit {
			uint8_t data;
			uint8_t key;
			uint8_t size;
		}
		key is relative to round of encryption, size if the length of same bytes
	*/
	type Unit struct {
		data uint8
		key  uint8
		size uint8
	}

	compress_box := [][]uint8{
		{0x78, 0x3f, 0x19, 0xd1, 0xc9, 0x29, 0x33, 0x99},
		{0x11, 0x9a, 0xb3, 0x4f, 0x7c, 0x0a, 0x81, 0x66},
		{0x5a, 0x6b, 0x8c, 0x3e, 0x2d, 0x1b, 0x0e, 0x07},
		{0x03, 0xac, 0x56, 0x2b, 0x15, 0x8a, 0x45, 0x22},
		{0x22, 0x6f, 0x11, 0x9a, 0xb3, 0x4f, 0x7c, 0x0a},
		{0x81, 0x66, 0x5a, 0x6b, 0x8c, 0x3e, 0x2d, 0x1b},
		{0x0e, 0x07, 0x03, 0xac, 0x56, 0x2b, 0x15, 0x8a},
		{0x45, 0x22, 0x11, 0x9a, 0xb3, 0x4f, 0x7c, 0x0a},
	}

	units := make([]Unit, 0)

	last_byte := uint8(0)
	for i := range src {
		if src[i] == last_byte && len(units) > 0 && units[len(units)-1].size < 255 {
			units[len(units)-1].size++
		} else {
			last_byte = src[i]
			if i == 0 {
				units = append(units, Unit{data: src[i], key: 0, size: 1})
				continue
			}
			j := (i - int(units[len(units)-1].size)) % 64
			round_key := (p.key >> j) | (p.key << (64 - j))
			subkey := compress_box[j%8][round_key%8]
			units[len(units)-1].key = subkey ^ uint8(p.key&0xff)
			units[len(units)-1].size ^= uint8(round_key)
			units[len(units)-1].data ^= subkey ^ uint8(p.key&0xff)
			units = append(units, Unit{data: src[i], key: 0, size: 1})
		}
	}

	result := make([]uint8, 0)
	for i := range units {
		result = append(result, units[i].data)
		result = append(result, units[i].key)
		result = append(result, units[i].size)
	}

	return result
}

func (p KurumiParserV2) DecryptSourceCode() []uint8 {
	return []uint8(`
#include <stdint.h>
void de(uint8_t *data, uint32_t len, uint8_t *dst, uint32_t dstlen) {
	uint64_t key = ` + strconv.Itoa(int(p.key)) + `;
	uint8_t compress_box[8][8] = {
		{0x78, 0x3f, 0x19, 0xd1, 0xc9, 0x29, 0x33, 0x99},
		{0x11, 0x9a, 0xb3, 0x4f, 0x7c, 0x0a, 0x81, 0x66},
		{0x5a, 0x6b, 0x8c, 0x3e, 0x2d, 0x1b, 0x0e, 0x07},
		{0x03, 0xac, 0x56, 0x2b, 0x15, 0x8a, 0x45, 0x22},
		{0x22, 0x6f, 0x11, 0x9a, 0xb3, 0x4f, 0x7c, 0x0a},
		{0x81, 0x66, 0x5a, 0x6b, 0x8c, 0x3e, 0x2d, 0x1b},
		{0x0e, 0x07, 0x03, 0xac, 0x56, 0x2b, 0x15, 0x8a},
		{0x45, 0x22, 0x11, 0x9a, 0xb3, 0x4f, 0x7c, 0x0a},
	};

	uint32_t unit_index = 0;
	uint32_t dst_index = 0;
	uint32_t j = 0;
	while(dst_index < dstlen && unit_index < (len / 3)) {
		j = dst_index % 64;
		uint8_t round_key = (key >> j) | (key << (64 - j));
		uint8_t subkey = compress_box[dst_index % 8][round_key % 8];
		uint8_t size = data[unit_index * 3 + 2] ^ (round_key & 0xff);
		for(uint32_t i = 0; i < size; i++) {
			dst[dst_index] = data[unit_index * 3] ^ subkey ^ (key & 0xff);
			dst_index++;
		}
		unit_index++;
	}
}
	`)
}

func GetKurumiParserV2(key uint64) KurumiParserV2 {
	return KurumiParserV2{key: key}
}
