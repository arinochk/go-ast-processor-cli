package analysis

import (
	"fmt"
	"go/token"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type AnalysisType int

const (
	VTA AnalysisType = iota
	CHA
)

type AnalyzerResult struct {
	CallGraph    *callgraph.Graph
	Fset         *token.FileSet
	ModulePath   string
	AnalysisType AnalysisType
	Duration     time.Duration
}

type AstAnalyzer interface {
	Analyze() (*AnalyzerResult, error)
}

func NewAstAnalyzer(config *packages.Config, analysisType AnalysisType) AstAnalyzer {
	switch analysisType {
	case VTA:
		return &VTAAnalyzer{config, analysisType}
	case CHA:
		return &CHAAnalyzer{config, analysisType}
	default:
		return &CHAAnalyzer{config, analysisType}
	}
}

type CHAAnalyzer struct {
	Config       *packages.Config
	AnalysisType AnalysisType
}

type VTAAnalyzer struct {
	Config       *packages.Config
	AnalysisType AnalysisType
}

func (analyzer *VTAAnalyzer) Analyze() (*AnalyzerResult, error) {
	startTime := time.Now()

	prog, err := getSSAProgram(analyzer.Config)
	if err != nil {
		slog.Error("Failed to build SSA program", "error", err)
		return nil, fmt.Errorf("could not build ssa program: %w", err)
	}
	slog.Info("Using Variable Type Analysis (VTA)")
	cg := vta.CallGraph(ssautil.AllFunctions(prog), cha.CallGraph(prog))
	slog.Info("VTA completed successfully")
	// Получаем путь модуля
	modulePath, err := GetModulePath(analyzer.Config.Dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get module path: %w", err)
	}

	// Фильтруем функции проекта
	filteredCg := filterProjectFunctions(cg, modulePath)

	duration := time.Since(startTime)

	slog.Info("Analysis completed",
		"type", VTA,
		"total_nodes", len(cg.Nodes),
		"filtered_nodes", len(filteredCg.Nodes),
		"module", modulePath,
		"duration", duration)

	return &AnalyzerResult{
		CallGraph:    filteredCg,
		Fset:         prog.Fset,
		ModulePath:   modulePath,
		AnalysisType: VTA,
		Duration:     duration,
	}, nil
}

func (analyzer *CHAAnalyzer) Analyze() (*AnalyzerResult, error) {
	startTime := time.Now()

	prog, err := getSSAProgram(analyzer.Config)
	if err != nil {
		slog.Error("Failed to build SSA program", "error", err)
		return nil, fmt.Errorf("could not build ssa program: %w", err)
	}

	slog.Info("Using Class Hierarchy Analysis (CHA)")
	cg := cha.CallGraph(prog)
	// Получаем путь модуля
	modulePath, err := GetModulePath(analyzer.Config.Dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get module path: %w", err)
	}

	// Фильтруем функции проекта
	filteredCg := filterProjectFunctions(cg, modulePath)

	duration := time.Since(startTime)

	slog.Info("Analysis completed",
		"type", CHA,
		"total_nodes", len(cg.Nodes),
		"filtered_nodes", len(filteredCg.Nodes),
		"module", modulePath,
		"duration", duration)

	return &AnalyzerResult{
		CallGraph:    filteredCg,
		Fset:         prog.Fset,
		ModulePath:   modulePath,
		AnalysisType: CHA,
		Duration:     duration,
	}, nil
}

func getSSAProgram(config *packages.Config) (*ssa.Program, error) {

	slog.Info("Loading packages", "dir", config.Dir)
	pkgs, err := packages.Load(config, "./...")
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages found in directory: %s", config.Dir)
	}

	slog.Info("Packages loaded", "count", len(pkgs))
	prog, _ := ssautil.AllPackages(pkgs, ssa.SanityCheckFunctions)
	prog.Build()
	return prog, nil
}

func GetModulePath(projectPath string) (string, error) {
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

func filterProjectFunctions(cg *callgraph.Graph, modulePath string) *callgraph.Graph {
	filteredGraph := callgraph.New(nil)
	nodeMap := make(map[*ssa.Function]*callgraph.Node)

	// Создаем узлы для функций проекта
	for _, node := range cg.Nodes {
		if node.Func != nil && node.Func.Pkg != nil && node.Func.Pkg.Pkg != nil {
			pkgPath := node.Func.Pkg.Pkg.Path()
			if strings.HasPrefix(pkgPath, modulePath) {
				newNode := filteredGraph.CreateNode(node.Func)
				nodeMap[node.Func] = newNode
			}
		}
	}

	// Добавляем ребра между узлами проекта
	for _, node := range cg.Nodes {
		if newNode, exists := nodeMap[node.Func]; exists {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					if calleeNode, exists := nodeMap[edge.Callee.Func]; exists {
						callgraph.AddEdge(newNode, edge.Site, calleeNode)
					}
				}
			}
		}
	}

	return filteredGraph
}
