package analysis

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/analysis/converter"
	"go-ast-processor-cli/internal/analysis/funcgraph"
	"go-ast-processor-cli/internal/analysis/pkgproc"
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
	vulnPkgsFinder     pkgproc.VulnPkgsFinder
	converter          converter.GraphConverter
	logger             *slog.Logger
}

func NewAnalyzer(
	logger *slog.Logger,
	resolver ModulePathResolverFunc,
	vulnPkgsFinder pkgproc.VulnPkgsFinder,
	converter converter.GraphConverter) Analyzer {
	return &defaultAnalyzer{
		modulePathResolver: resolver,
		logger:             logger,
		vulnPkgsFinder:     vulnPkgsFinder,
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

	pkgsPaths, err := a.vulnPkgsFinder.FindVulnPackages(ctx, projectPath, vulnFuncInfo.FileName, modulePath)
	if err != nil {
		return nil, fmt.Errorf("error while finding vulnerable packages: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	a.logger.Info("building SSA program")
	prog, fset, err := funcgraph.BuildProgram(pkgsPaths, projectPath)
	if err != nil {
		return nil, fmt.Errorf("error while building program: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	a.logger.Info("SSA program was built")

	vtaParams := funcgraph.GraphParams{
		ModulePath:  modulePath,
		PkgsPaths:   pkgsPaths,
		ProjectPath: projectPath,
		Fset:        fset,
		Program:     prog,
	}
	fset, chaGraph, err := funcgraph.NewGraphBuilder(a.logger).Build(ctx, vtaParams)
	if err != nil {
		return nil, fmt.Errorf("failed to build call graph using vta algorithm: %w", err)
	}
	duration := time.Since(startTime)
	a.logger.Info("vta analysis completed",
		"total_nodes", len(chaGraph.Nodes),
		"duration", duration)

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}
	targetFunc := funcgraph.FindTargetFunction(chaGraph, fset, vulnFuncInfo)
	callers := funcgraph.CollectCallers(chaGraph, targetFunc)
	callers[targetFunc] = true
	ptaStartTime := time.Now()
	ptaParams := funcgraph.GraphParams{
		ModulePath:  modulePath,
		PkgsPaths:   pkgsPaths,
		ProjectPath: projectPath,
		Fset:        fset,
		Program:     prog,
		FunctionSet: nil, // не ограничиваем
		Filter:      nil,
	}
	fset, ptaGraph, err := funcgraph.NewGraphBuilder(a.logger, funcgraph.WithStrategy(&funcgraph.PTAStrategy{Logger: a.logger})).Build(ctx, ptaParams)
	if err != nil {
		return nil, fmt.Errorf("failed to build call graph using pta algorithm: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}
	duration = time.Since(ptaStartTime)
	a.logger.Info("pta analysis completed",
		"total_nodes", len(chaGraph.Nodes),
		"duration", duration)

	tree, err := a.converter.Convert(ctx, ptaGraph, fset, modulePath, vulnFuncInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to convert google/x/tools pta funcgraph: %w", err)
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
