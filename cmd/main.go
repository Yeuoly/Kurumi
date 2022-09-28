package main

import (
	"io/ioutil"

	"github.com/Yeuoly/kurumi/ctrl"
)

func main() {
	filebytes, err := ioutil.ReadFile("./cmd/file/elf")
	if err != nil {
		panic(err)
	}

	err = ctrl.Build(filebytes, "kurumi-2", "122", "kurumi-mixer-default-4", "./cmd/file/out")
	if err != nil {
		panic(err)
	}
}
