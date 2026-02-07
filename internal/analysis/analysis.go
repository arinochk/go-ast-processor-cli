package analysis

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/analysis/converter"
	"go-ast-processor-cli/internal/analysis/xtools"
	"go-ast-processor-cli/internal/models"
	"golang.org/x/mod/modfile"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

type Analyzer interface {
	Analyze(ctx context.Context, projectPath string, vuln *models.VulnFuncInfo) (*models.Tree, error)
}

type defaultAnalyzer struct {
	modulePathResolver ModulePathResolverFunc
	graphBuilder       xtools.GraphBuilder
	converter          converter.GraphConverter
	logger             *slog.Logger
}

func NewAnalyzer(
	logger *slog.Logger,
	resolver ModulePathResolverFunc,
	graphBuilder xtools.GraphBuilder,
	converter converter.GraphConverter) Analyzer {
	return &defaultAnalyzer{
		modulePathResolver: resolver,
		graphBuilder:       graphBuilder,
		logger:             logger,
		converter:          converter,
	}
}

func (a defaultAnalyzer) Analyze(ctx context.Context, projectPath string, vulnFuncInfo *models.VulnFuncInfo) (*models.Tree, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	startTime := time.Now()
	modulePath, err := a.modulePathResolver(projectPath)
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

type ModulePathResolverFunc func(projectPath string) (string, error)

func NewModuleResolver(logger *slog.Logger) ModulePathResolverFunc {
	return func(projectPath string) (string, error) {
		logger.Info(fmt.Sprintf("Resolving module path: %s", projectPath))
		goModPath := filepath.Join(projectPath, "go.mod")
		data, err := os.ReadFile(goModPath)
		if err != nil {
			return "", fmt.Errorf("failed to read go.mod: %w", err)
		}

		modulePath := modfile.ModulePath(data)
		if modulePath == "" {
			return "", fmt.Errorf("no module path found in go.mod")
		}

		return modulePath, nil
	}
}
