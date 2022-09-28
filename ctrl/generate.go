package ctrl

import (
	"io/ioutil"
	"os/exec"
	"regexp"

	"strconv"

	"github.com/Yeuoly/kurumi/parser"
)

func BuildDstSource(src []byte, method string, key string, mixer string) []byte {
	var p parser.ParserInterface
	switch method {
	case "xor":
		xorkey, err := strconv.Atoi(key)
		if err != nil {
			return nil
		}
		p = parser.GetXorParser(uint8(xorkey))
	case "kurumi-1":
		p = parser.GetKurumiParserV1(key)
	case "kurumi-2":
		kurumikey, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil
		}
		p = parser.GetKurumiParserV2(kurumikey)
	}

	loadercode, err := ioutil.ReadFile("./loader/linux/x86.c")
	if err != nil {
		return nil
	}

	c_source := `
` + string(loadercode) + `
` + string(p.DecryptSourceCode()) + `
`

	enc := p.Encrypt(src)

	code_defination := `
char *code = "`
	for _, v := range enc {
		current := `\x` + strconv.FormatInt(int64(v), 16)
		//pad 0
		if len(current) == 3 {
			current = `\x0` + strconv.FormatInt(int64(v), 16)
		}
		code_defination += current
	}
	code_defination += `";
`

	main_code := `
extern char **environ;

int main(int argc, char **argv) {
	char buf[` + strconv.Itoa(len(src)) + `] = { 0 };
	char *err = NULL;
	memcpy(buf, code, ` + strconv.Itoa(len(src)) + `);
	de(code, ` + strconv.Itoa(len(enc)) + `, buf, ` + strconv.Itoa(len(src)) + `);
	LoadElf((void *)buf, ` + strconv.Itoa(len(src)) + `, argv, environ, &err);
}
`

	origin_score := c_source + code_defination + main_code

	//match functions
	re := regexp.MustCompile(`[\S]+\s+[\S]+\s*\(.*\)\s*\{`)
	matches := re.FindAllIndex([]byte(origin_score), -1)
	functions := make([][2]int, len(matches))
	for i, v := range matches {
		start_index := v[0]
		end_index := v[1] - 1
		quote_counter := 0
		for end_index < len(origin_score) {
			if origin_score[end_index] == '{' {
				quote_counter++
			} else if origin_score[end_index] == '}' {
				quote_counter--
				if quote_counter == 0 {
					break
				}
			}
			end_index++
		}
		functions[i] = [2]int{start_index, end_index}
	}

	//TODO: dynamic mixer level
	mixer_level := 1
	mixer_rate := func() float64 {
		switch mixer_level {
		case 1:
			return 0.2
		}
		return 0
	}()

	is_in_function := func(index int) bool {
		for _, v := range functions {
			if index >= v[0] && index <= v[1] {
				return true
			}
		}
		return false
	}

	//mixer
	re = regexp.MustCompile(`[^\n].*\n`)
	lines := re.FindAllIndex([]byte(origin_score), -1)
	mix_lines := int(float64(len(lines)) * mixer_rate)
	interval := len(lines) / mix_lines
	result := ""
	for i, v := range lines {
		if !is_in_function(v[0]) {
			result += origin_score[v[0]:v[1]] + "\n"
			continue
		}
		if i%interval == 0 {
			substr := origin_score[v[0]:v[1]]
			if ok, _ := regexp.MatchString(`;[\s\t]*\n`, substr); ok {
				result += substr + "\n" + parser.GetMixer(mixer) + "\n"
			} else {
				result += substr + "\n"
			}
		} else {
			result += origin_score[v[0]:v[1]] + "\n"
		}
	}

	return []byte(result)
}

func Build(src []byte, method string, key string, mixer string, dst string) error {
	src = BuildDstSource(src, method, key, mixer)
	//fmt.Println(string(src))
	//write to tmp file
	tmpdir, err := ioutil.TempDir("/tmp", "kurumi*")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(tmpdir+"/out.c", src, 0644)
	if err != nil {
		return err
	}

	//compile and strip symtab
	err = exec.Command("gcc", "-o", tmpdir+"/out", tmpdir+"/out.c", "-s").Run()
	if err != nil {
		return err
	}

	//mov to dst
	err = exec.Command("mv", tmpdir+"/out", dst).Run()
	if err != nil {
		return err
	}

	//remove tmpdir
	err = exec.Command("rm", "-rf", tmpdir).Run()
	if err != nil {
		return err
	}

	return nil
}
