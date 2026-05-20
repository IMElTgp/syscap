package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func getSyscallFields() error {
	for syscallID, syscallName := range syscallTable {
		_ = syscallID
		f, err := os.Open("/sys/kernel/tracing/events/syscalls/sys_enter_" + syscallName + "/format")
		if err != nil {
			fmt.Printf("skipping %s because of %s\n", syscallName, err.Error())
			continue
		}
		defer f.Close()

		var scanner = bufio.NewScanner(f)
		var seenBlankLine = false
		fields := make([]string, 0)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if line == "" {
				seenBlankLine = true
				continue
			}
			if !seenBlankLine {
				continue
			}
			if !strings.HasPrefix(line, "field:") {
				continue
			}
			line = strings.TrimPrefix(line, "field:")
			line = strings.TrimSuffix(line, ";")
			parts := strings.Split(line, ";")
			line = parts[0]

			var (
				Type      string
				fieldName string
			)

			// may contain multiple white spaces
			parts = strings.Split(line, " ")
			if len(parts) < 2 {
				continue
			}
			fieldName = parts[len(parts)-1]

			// consider fields whose names begin with _ as non-user fields
			if strings.HasPrefix(fieldName, "_") {
				continue
			}
			Type = strings.Join(parts[:len(parts)-1], " ")

			sep := " "
			if strings.HasSuffix(Type, "*") {
				sep = ""
			}
			fields = append(fields, strings.Join([]string{Type, fieldName}, sep))
		}
		fd, err := os.OpenFile("syscall_fields.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer fd.Close()
		w := bufio.NewWriter(fd)
		w.WriteString("\"" + syscallName + "\": {\n")
		for _, field := range fields {
			w.WriteString("    \"" + field + "\",\n")
		}
		w.WriteString("},\n")
		w.Flush()
	}
	return nil
}

/**
var syscallFields = make(map[string][]string)

syscallFields = map[string][]string{
	"read": []string{
		"unsigned int fd",
		"char *buf",
		"size_t count",
	},
}
*/
