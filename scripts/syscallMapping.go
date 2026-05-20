package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func processSyscallNameToIDMapping() {
	t, err := getRawText()
	if err != nil {
		fmt.Println(err.Error())
	}

	name, id, err := processRawText(t)
	if err != nil {
		fmt.Println(err.Error())
	}

	f, err := os.OpenFile("syscallNameToID.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer f.Close()

	for i := range name {
		var w = bufio.NewWriter(f)
		if _, err := w.WriteString(id[i] + ":" + " " + "\"" + name[i] + "\"" + ",\n"); err != nil {
			fmt.Println(err.Error())
		}
		w.Flush()
	}

	for i := range name {
		// build a reversed table
		var w = bufio.NewWriter(f)
		w.WriteString("\"" + name[i] + "\": " + id[i] + ",\n")
		w.Flush()
	}
}

func getRawText() (string, error) {
	out, err := exec.Command("sed", "-n", "1,400p", "/usr/include/asm/unistd_64.h").Output()
	if err != nil {
		return "", fmt.Errorf("failed to parse: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func processRawText(rawText string) (name []string, id []string, err error) {
	lines := strings.Split(rawText, "\n")

	for _, line := range lines {
		if !strings.HasPrefix(line, "#define ") {
			continue
		}

		line = strings.TrimPrefix(line, "#define ")
		if !strings.HasPrefix(line, "__NR_") {
			continue
		}

		line = strings.TrimPrefix(line, "__NR_")

		before, after, found := strings.Cut(line, " ")
		if !found {
			return nil, nil, fmt.Errorf("invalid kernel file format, causing: %w", err)
		}

		name = append(name, before)
		id = append(id, after)
	}
	return name, id, nil
}
