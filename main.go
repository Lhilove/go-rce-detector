package main

import (
	"fmt"
	"go/token"
	"gosentinel/rules"
	"gosentinel/scanner"
	"log"
	"os"
)

func main() {
	root := "./testdata"

	files, err := scanner.GetGoFiles(root)
	if err != nil {
		log.Fatal(err)
	}

	fset := token.NewFileSet()
	hasCritical := false

	for _, file := range files {
		node, _, err := scanner.ParseFile(file)
		if err != nil {
			log.Printf("failed to parse %s: %v\n", file, err)
			continue
		}

		fmt.Printf("Parsed: %s | Package: %s\n", file, node.Name.Name)

		findings := rules.DetectExecCommand(file, node, fset)

		for _, f := range findings {

			fmt.Printf("[%s] %s:%d\n", f.Severity, f.File, f.Line)
			fmt.Printf("    %s\n\n", f.Message)

			if f.Severity == "CRITICAL" {
				hasCritical = true
			}
		}
	}

	if hasCritical {
		fmt.Println("\n[!] CRITICAL RCE DETECTED - FAILING BUILD")
		os.Exit(1)
	}

	os.Exit(0)
}
