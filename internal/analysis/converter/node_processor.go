package converter

import (
	"fmt"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"strings"
)

type NodeFilter func(fn *ssa.Function, node *callgraph.Node, modulePath string, fset *token.FileSet) bool

func NewNodeFilter() NodeFilter {
	return func(fn *ssa.Function, node *callgraph.Node, modulePath string, fset *token.FileSet) bool {
		if fn == nil || node == nil || node.Func == nil || node.Func.Pkg == nil || node.Func.Pkg.Pkg == nil {
			return true
		}

		pkgPath := node.Func.Pkg.Pkg.Path()
		if !strings.HasPrefix(pkgPath, modulePath) {
			return true
		}

		position := fset.Position(fn.Pos())
		if !position.IsValid() {
			return true
		}

		// Пропускаем init функции
		if node.Func.Name() == "init" {
			return true
		}

		return false
	}
}

type NodeIdGenerator func(fn *ssa.Function, fset *token.FileSet) string

func NewNodeIDGenerator() NodeIdGenerator {
	return func(fn *ssa.Function, fset *token.FileSet) string {
		funcPos := fset.Position(fn.Pos())
		if fn.Pkg != nil && fn.Pkg.Pkg != nil {
			return fmt.Sprintf(models.KeyForNodeStructure, fn.Name(), funcPos.Filename, funcPos.Line)
		}
		return fn.Name()
	}
}
