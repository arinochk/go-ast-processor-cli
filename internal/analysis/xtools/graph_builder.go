package xtools

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log/slog"
	"strings"
)

type GraphBuilder interface {
	Build(ctx context.Context, projectPath string, modulePath string, funcInfo *models.VulnFuncInfo) (*token.FileSet, *callgraph.Graph, error)
}

func NewGraphBuilder(
	logger *slog.Logger,
	builder SsaBuilder,
	filter GraphFilter) GraphBuilder {
	return &graphBuilder{
		ssaBuilder:  builder,
		graphFilter: filter,
		logger:      logger,
	}
}

type graphBuilder struct {
	ssaBuilder  SsaBuilder
	graphFilter GraphFilter
	logger      *slog.Logger
}

func (graphBuilder graphBuilder) Build(
	ctx context.Context,
	projectPath string,
	modulePath string,
	funcInfo *models.VulnFuncInfo,
) (*token.FileSet, *callgraph.Graph, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}
	graphBuilder.logger.Info("Building SSA program")
	prog, err := graphBuilder.ssaBuilder.build(ctx, projectPath, funcInfo.FileName, modulePath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not build ssa program: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	graphBuilder.logger.Info("Building CHA call graph")
	chaGraph := cha.CallGraph(prog)
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	graphBuilder.logger.Info("CHA call graph has been built. Building Vta graph")
	vtaGraph := vta.CallGraph(ssautil.AllFunctions(prog), chaGraph)

	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	graphBuilder.logger.Info("VTA graph has been built.", "count of nodes", len(vtaGraph.Nodes))
	filteredGraph := graphBuilder.graphFilter(vtaGraph, modulePath)
	graphBuilder.logger.Info("Filtered VTA graph has been built.", "count of nodes", len(filteredGraph.Nodes))
	return prog.Fset, filteredGraph, nil
}

type GraphFilter func(cg *callgraph.Graph, modulePath string) *callgraph.Graph

func NewGraphFilter() GraphFilter {
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
