package main

import (
	"fmt"

	"github.com/yeuoly/kurumi/parser"
)

func main() {
	mixer := parser.GetMixer("kurumi-mixer-default-4")
	c_source := `
#include <stdio.h>

int main() {
	` + mixer + `
	printf("test\n");
}
	`
	fmt.Println(c_source)
}
