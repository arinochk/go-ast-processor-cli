package app

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/analysis"
	"go-ast-processor-cli/internal/analysis/converter"
	"go-ast-processor-cli/internal/analysis/xtools"
	"go-ast-processor-cli/internal/cmd"
	"go-ast-processor-cli/internal/tree"
	"log/slog"
)

type App struct {
	inputProcessor  cmd.InputProcessor
	outputProcessor cmd.OutputProcessor
	analyzer        analysis.Analyzer
	pathFuncFinder  tree.PathFuncFinder
}

func NewApp() *App {
	logger := setupLogger()
	modulePathResolver := analysis.NewModuleResolver(logger)

	pkgByFilePathFinder := xtools.NewPkgByFilePathFinder(logger)
	allProjectPkgsFinder := xtools.NewAllProjectPkgsFinder(logger)
	pkgDependenciesFinder := xtools.NewPkgDependenciesFinder(logger)
	vulnPkgsFinder := xtools.NewVulnPkgsFinder(logger, pkgByFilePathFinder, allProjectPkgsFinder, pkgDependenciesFinder)
	ssaBuilder := xtools.NewSsaBuilder(logger, vulnPkgsFinder)

	graphFilter := xtools.NewGraphFilter()
	graphBuilder := xtools.NewGraphBuilder(logger, ssaBuilder, graphFilter)

	nodeFilter := converter.NewNodeFilter()
	nodeIdGenerator := converter.NewNodeIDGenerator()
	ssaToDomainMapper := converter.NewSsaFunctionMapper()
	allNodesFinder := converter.NewAllNodesFinder(logger, nodeFilter, nodeIdGenerator, ssaToDomainMapper)

	edgesAdder := converter.NewEdgesAdder(logger, nodeFilter, nodeIdGenerator)

	connectionBuilder := converter.NewConnectionBuilder(logger, nodeFilter, nodeIdGenerator, edgesAdder)

	graphConverter := converter.NewGraphConverter(logger, allNodesFinder, connectionBuilder)

	analyzer := analysis.NewAnalyzer(logger, modulePathResolver, graphBuilder, graphConverter)
	return &App{
		inputProcessor:  cmd.NewCliProcessor(logger),
		outputProcessor: cmd.NewOuputProcessor(),
		analyzer:        analyzer,
		pathFuncFinder:  tree.NewPathFuncFinder(),
	}
}

func setupLogger() *slog.Logger {
	return slog.Default()
}

func (a *App) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return fmt.Errorf("operation cancelled: %w", ctx.Err())
	}
	projectPath, err := a.inputProcessor.ProcessProjectPathInput()
	if err != nil {
		return err
	}
	slog.Info("analysis started.")
	vulnFuncInfo, err := a.inputProcessor.ProcessTargetFunctionInput()
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("operation cancelled: %w", ctx.Err())
	}
	callgraph, err := a.analyzer.Analyze(ctx, projectPath, vulnFuncInfo)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("operation cancelled: %w", ctx.Err())
	}
	slog.Info(fmt.Sprintf("analysis finished. %d root functions found", len(callgraph.Roots)))
	functionCallPaths, err := a.pathFuncFinder.FindPath(ctx, callgraph, vulnFuncInfo)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("operation cancelled: %w", ctx.Err())
	}
	a.outputProcessor.Process(functionCallPaths)
	return nil
}
