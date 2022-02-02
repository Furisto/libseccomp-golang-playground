package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func main() {
	var syscalls = []string{"mount"}
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		panic(err)
	}

	fmt.Println("Dumping rules")

	read, write, err := os.Pipe()
	if err != nil {
		out, _ := fmt.Printf("could not create pipe for seccomp dump: %w", err)
		panic(out)
	}

	finished := make(chan []byte, 1)
	go func() {
		data, err := ioutil.ReadAll(read)
		if err != nil {
			fmt.Printf("could not read package filter: %v", err)
			read.Close()
		}
		if len(data) > 0 {
			fmt.Printf("filter data %v", string(data))
		} else {
			fmt.Printf("no seccomp filter data was available")
		}

		finished <- data
	}()

	err = filter.ExportPFC(write)
	write.Close()
	if err != nil {
		fmt.Printf("could not export package filter: %v", err)
	}

	select {
	case <-finished:
		fmt.Println("finished reading")
	case <-time.After(6 * time.Second):
		fmt.Println("finished waiting")
	}

	for _, syscall := range syscalls {
		fmt.Printf("ActNotify: %s\n", syscall)
		syscallID, err := libseccomp.GetSyscallFromName(syscall)
		if err != nil {
			panic(err)
		}
		fmt.Printf("syscall id is %d\n", syscallID)

		err = filter.AddRule(syscallID, libseccomp.ActNotify)
		if err != nil {
			panic(err)
		}
	}
	filter.Load()
	fmt.Println("Finish")
}
