package callgraph

import (
	"context"
	"fmt"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa/ssautil"
	"log/slog"
)

type CHAVTAStrategy struct {
	logger *slog.Logger
}

func (s *CHAVTAStrategy) Build(ctx context.Context, params GraphParams) (*token.FileSet, *callgraph.Graph, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}
	s.logger.Info("Building SSA program")
	prog, _, err := buildProgram(params.PkgsPaths, params.ProjectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load program: %w", err)
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
	filteredGraph := filterGraph(vtaGraph, params.ModulePath)
	s.logger.Info("Filtered VTA graph has been built.", "count of nodes", len(filteredGraph.Nodes))
	return prog.Fset, filteredGraph, nil
}
