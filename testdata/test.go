package testdata

import (
	"os/exec"
)

func SafeCase() {
	// SAFE: no user input, no shell
	exec.Command("ls", "-la")
}

func UnsafeCaseSimple() {
	// SHOULD BE FLAGGED
	exec.Command("sh", "-c", "echo hello")
}

func UnsafeCaseWithVar() {
	cmd := "ls"
	exec.Command(cmd)
}

func AnotherSafeCase() {
	exec.Command("git", "status")
}
