package ctrl

import (
	"io/ioutil"
	"os/exec"
	"strconv"

	"github.com/Yeuoly/kurumi/parser"
)

func BuildDstSource(src []byte, method string, key string) []byte {
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
	return []byte(c_source + code_defination + main_code)
}

func Build(src []byte, method string, key string, dst string) error {
	src = BuildDstSource(src, method, key)

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
