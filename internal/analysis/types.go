package analysis

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"time"
)

type modulePathResolver interface {
	ResolveModulePath(projectPath string) (string, error)
}
type Analyzer interface {
	Analyze(ctx context.Context, projectPath string, vuln *models.VulnFuncInfo) (*models.Tree, error)
}
type XToolsAnalyzerResult struct {
	CallGraph  *callgraph.Graph
	Fset       *token.FileSet
	ModulePath string
	Duration   time.Duration
}
