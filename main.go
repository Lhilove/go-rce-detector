package main

import (
	"fmt"
	"go/token"
	"gosentinel/rules"
	"gosentinel/scanner"
	"log"
)

func main() {
	root := "./testdata"

	files, err := scanner.GetGoFiles(root)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		node, _, err := scanner.ParseFile(file)
		if err != nil {
			log.Printf("failed to parse %s: %v\n", file, err)
			continue
		}
		fmt.Printf("Parsed: %s | Package: %s\n", file, node.Name.Name)

		findings := rules.DetectExecCommand(file, node, token.NewFileSet())

		for _, f := range findings {
			fmt.Printf("[%s] %s:%d\n",
				f.Severity,
				f.File,
				f.Line,
			)
			fmt.Printf("    %s\n\n", f.Message)
		}
	}
}
