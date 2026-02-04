package converter

import (
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"strings"
)

func newNodeFilter() nodeFilter {
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
