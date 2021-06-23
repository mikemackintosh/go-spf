package main

import (
	"fmt"
	"os"

	"github.com/mikemackintosh/go-spf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: spf <domain> <ip>")
		os.Exit(1)
	}

	r, err := spf.Get(os.Args[1])
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	result, ok := r.Validate(os.Args[2])
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	var not string
	if !ok {
		not = "not "
	}
	fmt.Printf("%v: %s is %sa permitted sender for %s", result, os.Args[2], not, os.Args[1])
}
