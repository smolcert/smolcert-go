// +build rust

package smolcert

import (
	"os"
	"os/exec"
	"testing"
)

func TestRustImplementation(t *testing.T) {
	cargoCmd := exec.Command("cargo", "test")
	cargoCmd.Dir = "./rust"
	cargoCmd.Stdout = os.Stdout
	cargoCmd.Stderr = os.Stderr

	if err := cargoCmd.Run(); err != nil {
		t.FailNow()
	}
}
