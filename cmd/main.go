package main

import (
	"io/ioutil"

	"github.com/yeuoly/kurumi/ctrl"
)

func main() {
	filebytes, err := ioutil.ReadFile("./cmd/file/elf")
	if err != nil {
		panic(err)
	}

	err = ctrl.Build(filebytes, ctrl.GeneratorConfig{
		Method:       "kurumi-2",
		Key:          "323144",
		Mixer:        "kurumi-mixer-default-4",
		AntiDebuuger: "kurumi-anti-debugger-1",
	}, "./cmd/file/out")
	if err != nil {
		panic(err)
	}
}
