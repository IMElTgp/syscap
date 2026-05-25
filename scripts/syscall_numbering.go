package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func outputSyscallNumber() {
	f, err := os.OpenFile("global_vars.txt", os.O_APPEND|os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	for no, name := range syscallTable {
		w.WriteString(fmt.Sprintf("#define __SYS_%s %d\n", strings.ToUpper(name), no))
	}
	w.Flush()
}

func fillSysPtrArgTable() {
	f, err := os.OpenFile("ptr_args.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	for _, name := range syscallTable {
		// [__SYS_<SYSCALL_NAME>] = mask,
		var mask uint8
		for i, arg := range syscallFields[name] {
			if strings.Contains(arg, "*") {
				mask |= (1 << i)
			}
		}
		w.WriteString(fmt.Sprintf("    [__SYS_%s] = %d,\n", strings.ToUpper(name), mask))
	}
	w.Flush()
}

func fillSysPtrArgTableForGo() {
	f, err := os.OpenFile("ptr_args_for_go.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	for no, name := range syscallTable {
		// no: mask,
		var mask uint8
		for i, arg := range syscallFields[name] {
			if strings.Contains(arg, "*") {
				mask |= (1 << uint8(i))
			}
		}
		fmt.Fprintf(w, "    %d: %d,\n", no, mask)
	}
}
