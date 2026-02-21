package funcgraph

import (
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"strings"
)

func BuildProgram(pkgsPaths []string, projectPath string) (*ssa.Program, *token.FileSet, error) {
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Dir:   projectPath,
		Tests: false,
	}
	initialPkgs, err := packages.Load(cfg, pkgsPaths...)
	if err != nil {
		return nil, nil, err
	}
	prog, _ := ssautil.Packages(initialPkgs, ssa.BuilderMode(0))
	prog.Build()
	return prog, prog.Fset, nil
}

func filterGraph(cg *callgraph.Graph, modulePath string) *callgraph.Graph {
	filtered := callgraph.New(nil)
	nodeMap := make(map[*ssa.Function]*callgraph.Node)

	for _, node := range cg.Nodes {
		if node.Func != nil && node.Func.Pkg != nil && node.Func.Pkg.Pkg != nil {
			pkgPath := node.Func.Pkg.Pkg.Path()
			if strings.HasPrefix(pkgPath, modulePath) {
				newNode := filtered.CreateNode(node.Func)
				nodeMap[node.Func] = newNode
			}
		}
	}

	for _, node := range cg.Nodes {
		if newNode, ok := nodeMap[node.Func]; ok {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					if calleeNode, ok := nodeMap[edge.Callee.Func]; ok {
						callgraph.AddEdge(newNode, edge.Site, calleeNode)
					}
				}
			}
		}
	}
	return filtered
}

func FindTargetFunction(cg *callgraph.Graph, fset *token.FileSet, info *models.VulnFuncInfo) *ssa.Function {
	for _, node := range cg.Nodes {
		if node.Func == nil {
			continue
		}

		fn := node.Func
		if fn.Pkg != nil && fn.Pkg.Pkg != nil && fn.Name() == info.FuncName {
			pos := fset.Position(fn.Pos())
			if strings.HasSuffix(pos.Filename, info.FileName) {
				return fn
			}
		}
	}

	return nil
}
func CollectCallers(cg *callgraph.Graph, target *ssa.Function) map[*ssa.Function]bool {
	inEdges := make(map[*ssa.Function][]*ssa.Function)
	for _, node := range cg.Nodes {
		if node.Func == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				inEdges[edge.Callee.Func] = append(inEdges[edge.Callee.Func], node.Func)
			}
		}
	}

	visited := make(map[*ssa.Function]bool)
	queue := []*ssa.Function{target}
	visited[target] = true

	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for _, caller := range inEdges[f] {
			if !visited[caller] {
				visited[caller] = true
				queue = append(queue, caller)
			}
		}
	}
	return visited
}
