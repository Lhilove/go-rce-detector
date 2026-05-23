package rules

import (
	"go/ast"
	"go/token"
)

type Finding struct {
	File     string
	Line     int
	Severity string
	Message  string
}

func DetectExecCommand(file string, node ast.Node, fset *token.FileSet) []Finding {
	var findings []Finding
	tainted := make(map[string]bool)

	ast.Inspect(node, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if ok {
			for _, rhs := range assign.Rhs {
				if ident, ok := rhs.(*ast.Ident); ok {
					tainted[ident.Name] = true
				}
			}
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		if x.Name != "exec" || sel.Sel.Name != "Command" {
			return true
		}

		line := fset.Position(call.Pos()).Line

		// Safe

		severity := "LOW"
		msg := "exec.Command used"

		// no argument - unusual
		if len(call.Args) == 0 {
			severity = "MEDIUM"
			msg = "exec.Command called with no arguments"
		}

		// check shell usuage: sh -c

		if len(call.Args) >= 2 {
			arg1, ok1 := call.Args[0].(*ast.BasicLit)
			arg2, ok2 := call.Args[1].(*ast.BasicLit)

			if ok1 && ok2 {
				if arg1.Value == "\"sh\"" && arg2.Value == "\"-c\"" {
					severity = "CRITICAL"
					msg = "Possible RCE: shell execution via sh -c"
				}
			}
		}

		// detecting dynamic input

		for _, arg := range call.Args {

			// literal safe value
			if _, ok := arg.(*ast.BasicLit); ok {
				continue
			}

			// identifier for unsafe variables
			if id, ok := arg.(*ast.Ident); ok {
				if tainted[id.Name] {
					severity = "CRITICAL"
					msg = "RCE: tainted variable passed into exec.Command"
				} else {
					severity = "HIGH"
					msg = "Suspicious variable used in exec.Command"
				}
			}
		}

		findings = append(findings, Finding{
			File:     file,
			Line:     line,
			Severity: severity,
			Message:  msg,
		})

		return true

	})

	return findings
}

func isIdentifier(n ast.Expr) (string, bool) {
	id, ok := n.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}
