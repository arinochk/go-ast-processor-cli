package xtools

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa/ssautil"
	"log/slog"
)

type defaultGraphBuilder struct {
	ssaBuilder  ssaBuilder
	graphFilter graphFilter
	logger      *slog.Logger
}

func (graphBuilder defaultGraphBuilder) Build(
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
