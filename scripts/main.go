package main

import (
	"fmt"

	"github.com/IMElTgp/syscap/internal"
)

var syscallTable = internal.SyscallTable
var syscallFields = internal.SyscallFields
var reversedSyscallTable = internal.ReversedSyscallTable

func main() {
	processSyscallNameToIDMapping()
	if err := getSyscallFields(); err != nil {
		fmt.Println(err.Error())
	}
	outputSyscallNumber()
	fillSysPtrArgTable()
	fillSysPtrArgTableForGo()
}
