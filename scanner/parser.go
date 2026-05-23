package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
)

func ParseFile(filepath string) (*ast.File, *token.FileSet, error) {
	fset := token.NewFileSet()

	node, err := parser.ParseFile(
		fset,
		filepath,
		nil,
		parser.ParseComments,
	)

	if err != nil {
		return nil, nil, err
	}
	return node, fset, nil
}
