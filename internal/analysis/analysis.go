package analysis

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/analysis/converter"
	"go-ast-processor-cli/internal/analysis/xtools"
	"go-ast-processor-cli/internal/models"
	"log/slog"
	"time"
)

type defaultAnalyzer struct {
	modulePathResolver modulePathResolver
	graphBuilder       xtools.GraphBuilder
	converter          converter.GraphConverter
	logger             *slog.Logger
}

func NewDefaultAnalyzer(logger *slog.Logger) Analyzer {
	return &defaultAnalyzer{
		modulePathResolver: newModuleResolver(logger),
		graphBuilder:       xtools.NewGraphBuilder(logger),
		logger:             logger,
		converter:          converter.NewGraphConverter(logger),
	}
}

func (a defaultAnalyzer) Analyze(ctx context.Context, projectPath string, vulnFuncInfo *models.VulnFuncInfo) (*models.Tree, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	startTime := time.Now()
	modulePath, err := a.modulePathResolver.ResolveModulePath(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve module path: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	fset, graph, err := a.graphBuilder.Build(ctx, projectPath, modulePath, vulnFuncInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to build graph: %w", err)
	}
	duration := time.Since(startTime)
	a.logger.Info("Analysis completed",
		"total_nodes", len(graph.Nodes),
		"duration", duration)

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	tree, err := a.converter.Convert(ctx, graph, fset, modulePath, vulnFuncInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to convert google/x/tools vta graph: %w", err)
	}
	return tree, nil
}
