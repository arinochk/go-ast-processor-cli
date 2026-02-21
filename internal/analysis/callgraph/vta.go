package callgraph

import (
	"context"
	"fmt"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log/slog"
	"strings"
	"time"
)

type CHAVTAStrategy struct {
	logger *slog.Logger
}

func (s *CHAVTAStrategy) Build(ctx context.Context, graphParams GraphParams) (*token.FileSet, *callgraph.Graph, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}
	s.logger.Info("Building SSA program")
	prog, err := s.buildSSA(graphParams.PkgsPaths, graphParams.ProjectPath, graphParams.FuncInfo.FileName, graphParams.ModulePath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not buildSSA ssa program: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	s.logger.Info("Building CHA call graph")
	chaGraph := cha.CallGraph(prog)
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	s.logger.Info("CHA call graph has been built. Building Vta graph")
	vtaGraph := vta.CallGraph(ssautil.AllFunctions(prog), chaGraph)

	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	s.logger.Info("VTA graph has been built.", "count of nodes", len(vtaGraph.Nodes))
	filteredGraph := s.filterGraph(vtaGraph, graphParams.ModulePath)
	s.logger.Info("Filtered VTA graph has been built.", "count of nodes", len(filteredGraph.Nodes))
	return prog.Fset, filteredGraph, nil
}

func (s *CHAVTAStrategy) buildSSA(pkgsPaths []string, projectPath, filePath, modulePath string) (*ssa.Program, error) {
	s.logger.Info("Loading packages for SSA",
		"project", projectPath, "file", filePath)
	start := time.Now()

	s.logger.Info("Target packages for analysis",
		"count", len(pkgsPaths), "packages", pkgsPaths)
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Dir:   projectPath,
		Tests: false,
	}

	initialPkgs, err := packages.Load(cfg, pkgsPaths...)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	prog, _ := ssautil.Packages(initialPkgs, ssa.BuilderMode(0))
	prog.Build()
	s.logger.Info("Analysis complete", "duration", time.Since(start))
	return prog, nil
}

func (s *CHAVTAStrategy) filterGraph(cg *callgraph.Graph, modulePath string) *callgraph.Graph {
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
