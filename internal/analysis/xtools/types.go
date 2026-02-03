package xtools

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

type GraphBuilder interface {
	Build(ctx context.Context, projectPath string, modulePath string, funcInfo *models.VulnFuncInfo) (*token.FileSet, *callgraph.Graph, error)
}

type vulnPkgsFinder interface {
	findVulnPackages(ctx context.Context, projectPath, filePath, modulePath string) ([]string, error)
}

type pkgDependenciesFinder interface {
	getAllPkgDependencies(ctx context.Context, projectPath, targetPkg string, allPkgs []string, maxDepth int) ([]string, error)
}

type ssaBuilder interface {
	build(ctx context.Context, projectPath, filePath, modulePath string) (*ssa.Program, error)
}

type allProjectPkgsFinder func(ctx context.Context, projectPath, modulePath string) ([]string, error)

type pkgImportsFinder func(projectPath, pkgPath string) ([]string, error)

type pkgByFilePathFinder func(ctx context.Context, projectPath, filePath string) (string, error)

type graphFilter func(cg *callgraph.Graph, modulePath string) *callgraph.Graph
