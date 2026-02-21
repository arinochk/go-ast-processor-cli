package funcgraph

import (
	"context"
	"fmt"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
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

	var prog *ssa.Program
	var fset *token.FileSet
	var err error

	if params.Program != nil {
		prog = params.Program
		fset = params.Fset
	} else {
		prog, fset, err = BuildProgram(params.PkgsPaths, params.ProjectPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load program: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, fmt.Errorf("context cancelled: %w", err)
		}

	}
	s.logger.Info("Building CHA call funcgraph")
	chaGraph := cha.CallGraph(prog)
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	s.logger.Info("CHA call funcgraph has been built. Building Vta funcgraph")
	vtaGraph := vta.CallGraph(ssautil.AllFunctions(prog), chaGraph)

	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}

	s.logger.Info("VTA funcgraph has been built.", "count of nodes", len(vtaGraph.Nodes))
	filteredGraph := filterGraph(vtaGraph, params.ModulePath)
	s.logger.Info("Filtered VTA funcgraph has been built.", "count of nodes", len(filteredGraph.Nodes))
	return fset, filteredGraph, nil
}
