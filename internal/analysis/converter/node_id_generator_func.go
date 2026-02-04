package converter

import (
	"fmt"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/ssa"
)

func newNodeIDGenerator() nodeIdGenerator {
	return func(fn *ssa.Function, fset *token.FileSet) string {
		funcPos := fset.Position(fn.Pos())
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			return fmt.Sprintf(models.KeyForNodeStructure, fn.Name(), funcPos.Filename, funcPos.Line)
		}
		return fn.Name()
	}
}
