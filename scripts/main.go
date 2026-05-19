package main

import "fmt"

func main() {
	initTable()
	processSyscallNameToIDMapping()
	if err := getSyscallFields(); err != nil {
		fmt.Println(err.Error())
	}
}
