package funcgraph

import (
	"context"
	"fmt"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
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
	}

	cfg := config.NewDefault()

	scopeSet := make(map[string]bool)
	for _, p := range params.PkgsPaths {
		scopeSet[p] = true
	}
	filter := func(fn *ssa.Function) bool {
		return fn.Pkg != nil && fn.Pkg.Pkg != nil && scopeSet[fn.Pkg.Pkg.Path()]
	}

	ptrResult, err := ptr.DoPointerAnalysis(cfg, prog, filter, params.FunctionSet)
	if err != nil {
		return nil, nil, fmt.Errorf("pointer analysis failed: %w", err)
	}

	final := filterGraph(ptrResult.CallGraph, params.ModulePath)
	s.Logger.Info("Pointer analysis completed", "nodes", len(final.Nodes))

	return fset, final, nil
}
