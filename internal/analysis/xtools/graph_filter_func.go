package xtools

import (
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"strings"
)

func newGraphFilter() graphFilter {
	return func(cg *callgraph.Graph, modulePath string) *callgraph.Graph {
		filteredGraph := callgraph.New(nil)
		nodeMap := make(map[*ssa.Function]*callgraph.Node)

		// Создаем узлы для функций проекта
		for _, node := range cg.Nodes {
			if node.Func != nil && node.Func.Pkg != nil && node.Func.Pkg.Pkg != nil {
				pkgPath := node.Func.Pkg.Pkg.Path()
				if strings.HasPrefix(pkgPath, modulePath) {
					newNode := filteredGraph.CreateNode(node.Func)
					nodeMap[node.Func] = newNode
				}
			}
		}

		// Добавляем ребра между узлами проекта
		for _, node := range cg.Nodes {
			if newNode, exists := nodeMap[node.Func]; exists {
				for _, edge := range node.Out {
					if edge.Callee != nil && edge.Callee.Func != nil {
						if calleeNode, exists := nodeMap[edge.Callee.Func]; exists {
							callgraph.AddEdge(newNode, edge.Site, calleeNode)
						}
					}
				}
			}
		}

		return filteredGraph
	}
}
