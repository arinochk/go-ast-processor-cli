package main

import (
	"fmt"
	"go-ast-processor-cli/internal/analysis"
	"go-ast-processor-cli/internal/cmd"
	"go-ast-processor-cli/internal/tree"
	"log"
	"log/slog"
	"strings"
)

func main() {
	run()
}

func run() {
	inputProcessor := cmd.NewCliProcessor()
	AppConfig, err := inputProcessor.ProcessAnalysisConfInput()
	if err != nil {
		log.Fatal(err)
	}
	slog.Info("analysis started.")

	analyzeType, err := inputProcessor.ProcessAnalysisTypeInput()
	if err != nil {
		log.Fatal(err)
	}
	parseRes, err := analysis.NewAstAnalyzer(AppConfig.Config, analyzeType).Analyze()
	if err != nil {
		log.Fatal(err)
	}

	callGraph, err := analysis.NewGraphToDtoConverter(parseRes).ConvertToDto()
	if err != nil {
		log.Fatal(err)
	}

	slog.Info(fmt.Sprintf("analysis finished. %d root functions found", len(callGraph.Roots)))
	slog.Info(fmt.Sprintf("Analysis type: %v, Duration: %v", parseRes.AnalysisType, parseRes.Duration))

	funcPkgPath, funcName, filename, line, err := inputProcessor.ProcessTargetFunctionInput()
	if err != nil {
		log.Fatal(err)
	}

	slog.Info(fmt.Sprintf("Searching for call paths to: %s.%s", funcPkgPath, funcName))

	functionCallPaths, err := tree.NewPathFuncFinder(callGraph).FindPath(funcPkgPath, funcName, filename, line)
	if err != nil {
		log.Fatal(err)
	}

	if len(functionCallPaths) == 0 {
		slog.Info("No call paths found for the target function")
		return
	}

	slog.Info(fmt.Sprintf("Found %d call path(s):", len(functionCallPaths)))

	for i, path := range functionCallPaths {
		slog.Info(fmt.Sprintf("Path %d:", i+1))

		// Путь хранится в порядке от вызывающих к целевой функции
		// Разворачиваем для более естественного отображения
		for j := len(path) - 1; j >= 0; j-- {
			node := path[j]
			if node.FuncInfo != nil {
				callerInfo := fmt.Sprintf("  → %s.%s",
					node.FuncInfo.PkgPath,
					node.FuncInfo.Name)

				if node.FuncInfo.FileName != "" {
					callerInfo += fmt.Sprintf(" (file: %s", node.FuncInfo.FileName)
					if node.FuncInfo.Line > 0 {
						callerInfo += fmt.Sprintf(", line: %d", node.FuncInfo.Line)
					}
					callerInfo += ")"
				}

				slog.Info(callerInfo)
			}
		}
		slog.Info(strings.Repeat("-", 50))
	}
}
