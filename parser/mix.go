package parser

import (
	"math/rand"
	"strconv"
	"time"
)

type Mix struct {
	Name string
	Gen  func() string
	Os   []string
}

type Mixer struct {
	// mixe database
	mixes map[string]Mix
}

func (m *Mixer) NewMixer(name string, gen func() string, os ...string) {
	m.mixes[name] = Mix{
		Name: name,
		Gen:  gen,
		Os:   os,
	}
}

func (m *Mixer) GetMixer(name string) string {
	if mix, ok := m.mixes[name]; ok {
		return mix.Gen()
	}
	return ""
}

var defaultMixer = Mixer{
	mixes: make(map[string]Mix),
}

func NewMixer(name string, gen func() string) {
	defaultMixer.NewMixer(name, gen)
}

func GetMixer(name string) string {
	return defaultMixer.GetMixer(name)
}

func init() {
	rand.Seed(time.Now().Unix())

	var kurumi_mixer_default_1_label_base = 0

	NewMixer("kurumi-mixer-default-1", func() string {
		kurumi_mixer_default_1_label_base++
		return `
{
	empty(22);
	asm(
		"pushq %rax;"
		"xorq %rax, %rax;"
		"testq %rax, %rax;"
		"je label` + strconv.Itoa(kurumi_mixer_default_1_label_base) + `;"
		".byte 0x5e;"
		"addq %rbx, %rax;"
		".byte 0x7f;"
		"xorq %rax, %rax;"
		"testq %rax, %rax;"
		".byte 0x88, 0x5e, 0x01;"
		"label` + strconv.Itoa(kurumi_mixer_default_1_label_base) + `:"
		"popq %rax;"
	);
}
		`
	})

	NewMixer("kurumi-mixer-default-2", func() string {
		random_junk := make([]int, 0)
		for i := 0; i < 25; i++ {
			random_junk = append(random_junk, rand.Intn(255))
		}

		junk_str := strconv.Itoa(random_junk[0])
		for i := 1; i < 25; i++ {
			junk_str += ", " + strconv.Itoa(random_junk[i])
		}

		return `
asm(
	"jz label1;"
	"jnz label1;"
	".byte ` + junk_str + `;"
	"label1:"
)
		`
	})

	NewMixer("kurumi-mixer-default-3", func() string {
		random_junk := make([]int, 0)
		junk_length := rand.Intn(25) + 13
		for i := 0; i < junk_length; i++ {
			random_junk = append(random_junk, rand.Intn(255))
		}

		junk_str := strconv.Itoa(random_junk[0])
		for i := 1; i < junk_length; i++ {
			junk_str += ", " + strconv.Itoa(random_junk[i])
		}

		return `
empty(666);
asm(
	"pushq %rax;"
	"call label1;"
	".byte ` + junk_str + `;"
	"label1:"
	//do add [esp] to bypass junk bytes
	"movq $` + strconv.Itoa(junk_length+13) + `, %rax;"
	"addq %rax, (%rsp);"
	"ret;"
	".byte 0x92;"
	"popq %rax;"
);
		`
	})

	var kurumi_mixer_default_4_label_base = 0
	var kurumi_mixer_default_4_junk_base = 0
	var kurumi_mixer_default_4_final_base = 0

	NewMixer("kurumi-mixer-default-4", func() string {
		kurumi_mixer_default_4_final_base++
		asm := ""

		junk_labels := make(map[int]string, 0)
		for i := 0; i < 188; i++ {
			junk_labels[i] = "label" + strconv.Itoa(kurumi_mixer_default_4_label_base)
			kurumi_mixer_default_4_label_base++
		}

		//generate a jumk routine
		//our target is to make gdb flying away, so that real code can execute hiddenly
		//mix junk_labels
		routine := []int{}
		for i := 0; i < 188; i++ {
			routine = append(routine, i)
		}
		for i := 0; i < 187; i++ {
			current_index := rand.Intn(188-i) + i
			routine[i], routine[current_index] = routine[current_index], routine[i]
		}

		//generate junk asm
		junk_asm := make(map[int]string, 188)

		for i := 0; i < 187; i++ {
			junk_bytes := make([]int, 0)
			junk_length := rand.Intn(9) + 8
			for j := 0; j < junk_length; j++ {
				junk_bytes = append(junk_bytes, rand.Intn(255))
			}
			junk_str := strconv.Itoa(junk_bytes[0])
			for j := 1; j < junk_length; j++ {
				junk_str += ", " + strconv.Itoa(junk_bytes[j])
			}

			junk_asm[routine[i]] = `"` + junk_labels[routine[i]] + `:"
			"pushq %rax;"
			"xorq %rax, %rax;"
			"testq %rax, %rax;"
			"leaq ` + strconv.Itoa(junk_length+4) + `(%rip), %rax;"
			"jmp *%rax;"
			".byte ` + junk_str + `;"
			"jne junk_` + strconv.Itoa(i+kurumi_mixer_default_4_junk_base) + `;"
			"popq %rax;"
			"jz ` + junk_labels[routine[i+1]] + `;"
			"jnz ` + junk_labels[routine[i+1]] + `;"
			".byte 0x5e;"
			"addq %rbx, %rax;"
			".byte 0x7f;"
			"xorq %rax, %rax;"
			"testq %rax, %rax;"
			".byte 0x88, 0x5e, 0x01;"
			"junk_` + strconv.Itoa(i+kurumi_mixer_default_4_junk_base) + `:"
			"popq %rax;"
		`
		}

		junk_asm[routine[187]] = `"` + junk_labels[routine[187]] + `:"
			"pushq %rax;"
			"xorq %rax, %rax;"
			"testq %rax, %rax;"
			"leaq 6(%rip), %rax;"
			"jmp *%rax;"
			".byte 0x48, 0x01;"
			"jne junk_` + strconv.Itoa(187+kurumi_mixer_default_4_junk_base) + `;"
			"popq %rax;"
			"jz final_` + strconv.Itoa(kurumi_mixer_default_4_final_base) + `;"
			"jnz final_` + strconv.Itoa(kurumi_mixer_default_4_final_base) + `;"
			".byte 0x5e;"
			"addq %rbx, %rax;"
			".byte 0x7f;"
			"xorq %rax, %rax;"
			"testq %rax, %rax;"
			".byte 0x88, 0x5e, 0x01;"
			"junk_` + strconv.Itoa(187+kurumi_mixer_default_4_junk_base) + `:"
			"popq %rax;"
		`

		kurumi_mixer_default_4_junk_base += 188

		for i := 0; i < 188; i++ {
			asm += junk_asm[i]
		}

		return `
empty(663);
asm(
	"movq $233, %r12;"
    "movq $243, %r13;"
    "subq %r13, %r12;"
    "addq $10, %r12;"
    "testq %r12, %r12;"
	"jz ` + junk_labels[routine[0]] + `;"
	` + asm + `
	"final_` + strconv.Itoa(kurumi_mixer_default_4_final_base) + `:"
);
		`
	})
}
