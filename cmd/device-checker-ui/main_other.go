//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("Compliance Agent desktop UI preview is currently available on Windows. Run `device-checker status` for the local read-only report.")
}
