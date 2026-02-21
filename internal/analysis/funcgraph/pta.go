package funcgraph

import (
	"context"
	"fmt"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"log/slog"
)

type PTAStrategy struct {
	Logger *slog.Logger
}

func (s *PTAStrategy) Build(ctx context.Context, params GraphParams) (*token.FileSet, *callgraph.Graph, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}
	s.Logger.Info("Scope packages for Argot analysis", "count", len(params.PkgsPaths), "packages", params.PkgsPaths)

	if params.State == nil {
		return nil, nil, fmt.Errorf("PTAStrategy requires State in GraphParams")
	}
	state := params.State
	prog := state.Program
	fset := prog.Fset

	// Определяем фильтр: если передан FunctionSet, фильтр не нужен.
	// Иначе используем явно заданный Filter (может быть nil).
	var filter func(*ssa.Function) bool
	if params.FunctionSet != nil {
		filter = nil
	} else {
		filter = params.Filter
	}

	ptrResult, err := ptr.PointerAnalysis(state, filter, params.FunctionSet)
	if err != nil {
		return nil, nil, fmt.Errorf("pointer analysis failed: %w", err)
	}

	final := filterGraph(ptrResult.CallGraph, params.ModulePath)
	s.Logger.Info("Pointer analysis completed", "nodes", len(final.Nodes))

	return fset, final, nil
}
