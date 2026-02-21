package callgraph

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"log/slog"
)

type GraphParams struct {
	PkgsPaths   []string
	ProjectPath string
	ModulePath  string
	FuncInfo    *models.VulnFuncInfo

	Program *ssa.Program
	Fset    *token.FileSet

	FunctionSet map[*ssa.Function]bool
}

type GraphBuilder interface {
	Build(ctx context.Context, graphParams GraphParams) (*token.FileSet, *callgraph.Graph, error)
}

type GraphBuildingStrategy interface {
	Build(ctx context.Context, graphParams GraphParams) (*token.FileSet, *callgraph.Graph, error)
}

type graphBuilder struct {
	strategy GraphBuildingStrategy
}

func (b *graphBuilder) Build(ctx context.Context, graphParams GraphParams) (*token.FileSet, *callgraph.Graph, error) {
	return b.strategy.Build(ctx, graphParams)
}

type GraphBuilderOption func(*graphBuilder)

func WithStrategy(strategy GraphBuildingStrategy) GraphBuilderOption {
	return func(g *graphBuilder) {
		g.strategy = strategy
	}
}

func NewGraphBuilder(
	logger *slog.Logger,
	opts ...GraphBuilderOption,
) GraphBuilder {
	g := &graphBuilder{
		strategy: &CHAVTAStrategy{
			logger: logger,
		},
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}
