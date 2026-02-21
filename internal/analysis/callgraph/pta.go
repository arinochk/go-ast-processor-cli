package callgraph

import (
	"context"
	"fmt"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/analysis/ptr"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"log/slog"
)

type PTAStrategy struct {
	logger *slog.Logger
}

func (s *PTAStrategy) Build(ctx context.Context, graphParams GraphParams) (*token.FileSet, *callgraph.Graph, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("context cancelled: %w", err)
	}
	s.logger.Info("Scope packages for Argot analysis", "count", len(graphParams.PkgsPaths), "packages", graphParams.PkgsPaths)

	cfg := config.NewDefault()

	configState := config.NewState(cfg, graphParams.ProjectPath, graphParams.PkgsPaths, config.LoadOptions{})

	programStateResult := loadprogram.NewState(configState)
	if programStateResult.Error() != nil {
		return nil, nil, fmt.Errorf("failed to load program: %w", programStateResult.Error())
	}
	programState, err := programStateResult.Value()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load program: %w", err)
	}
	s.logger.Info("Program loaded", "packages", len(programState.Program.AllPackages()))

	scopeSet := make(map[string]bool)
	for _, p := range graphParams.PkgsPaths {
		scopeSet[p] = true
	}
	filter := func(fn *ssa.Function) bool {
		if fn.Pkg == nil || fn.Pkg.Pkg == nil {
			return false
		}
		return scopeSet[fn.Pkg.Pkg.Path()]
	}

	ptrResult, err := ptr.DoPointerAnalysis(
		programState.Config,
		programState.Program,
		filter,
		graphParams.FunctionSet,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("pointer analysis failed: %w", err)
	}
	s.logger.Info("Pointer analysis completed", "nodes", len(ptrResult.CallGraph.Nodes))

	return programState.Program.Fset, ptrResult.CallGraph, nil
}
