package xtools

import (
	"context"
	"fmt"
	"golang.org/x/tools/go/packages"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type VulnPkgsFinder interface {
	findVulnPackages(ctx context.Context, projectPath, filePath, modulePath string) ([]string, error)
}

type defaultVulnPkgsFinder struct {
	logger                *slog.Logger
	pkgByFilePathFinder   PkgByFilePathFinder
	allProjectPkgsFinder  AllProjectPkgsFinder
	pkgDependenciesFinder PkgDependenciesFinder
}

func NewVulnPkgsFinder(
	logger *slog.Logger,
	pkgByFilePathFinder PkgByFilePathFinder,
	allProjectPkgsFinder AllProjectPkgsFinder,
	pkgDependenciesFinder PkgDependenciesFinder,
) VulnPkgsFinder {
	return &defaultVulnPkgsFinder{
		logger:                logger,
		pkgByFilePathFinder:   pkgByFilePathFinder,
		allProjectPkgsFinder:  allProjectPkgsFinder,
		pkgDependenciesFinder: pkgDependenciesFinder,
	}
}

func (finder defaultVulnPkgsFinder) findVulnPackages(ctx context.Context, projectPath, filePath, modulePath string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	targetPkg, err := finder.pkgByFilePathFinder(ctx, projectPath, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerable target package: %w", err)
	}

	finder.logger.Info("Target package found", "package", targetPkg)

	allPkgs, err := finder.allProjectPkgsFinder(ctx, projectPath, modulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get all packages: %w", err)
	}
	finder.logger.Info("found total packages", "count", len(allPkgs))

	const maxDepth = 10
	deps, err := finder.pkgDependenciesFinder.getAllPkgDependencies(ctx, projectPath, targetPkg, allPkgs, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to get all dependencies: %w", err)
	}
	result := make([]string, 0, len(deps)+1)
	result = append(result, targetPkg)
	result = append(result, deps...)

	unique := make(map[string]bool)
	finalResult := make([]string, 0)
	for _, pkg := range result {
		if !unique[pkg] {
			unique[pkg] = true
			finalResult = append(finalResult, pkg)
		}
	}

	finder.logger.Info("Packages for SSA analysis", "count", len(finalResult), "packages", finalResult)

	return finalResult, nil
}

type PkgByFilePathFinder func(ctx context.Context, projectPath, filePath string) (string, error)

func NewPkgByFilePathFinder(logger *slog.Logger) PkgByFilePathFinder {
	return func(ctx context.Context, projectRoot, filePath string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("operation cancelled: %w", err)
		}

		logger.Debug("finding package by file path", "path", filePath)
		cfg := &packages.Config{
			Mode: packages.NeedName | packages.NeedFiles,
			Dir:  projectRoot,
			Env:  append(os.Environ(), "GO111MODULE=on"),
		}

		pattern := "file=" + filePath
		pkgs, err := packages.Load(cfg, pattern)
		if err != nil {
			if ctx.Err() != nil {
				return "", fmt.Errorf("operation cancelled: %w", ctx.Err())
			}
			logger.Error("failed to get package for filename", "path", filePath, "err", err)
			return "", fmt.Errorf("failed to load package for file %s: %w", filePath, err)
		}

		if len(pkgs) == 0 || pkgs[0].Name == "" {
			logger.Error("no packages found for file path", "path", filePath)
			return "", fmt.Errorf("no package found for file %s", filePath)
		}
		return pkgs[0].PkgPath, nil
	}
}

type AllProjectPkgsFinder func(ctx context.Context, projectPath, modulePath string) ([]string, error)

func NewAllProjectPkgsFinder(logger *slog.Logger) AllProjectPkgsFinder {
	return func(ctx context.Context, projectPath, modulePath string) ([]string, error) {
		logger.Debug("running go list", "dir", projectPath)

		cmd := exec.CommandContext(ctx, "go", "list", "./...")
		cmd.Dir = projectPath
		output, err := cmd.Output()
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("operation cancelled: %w", ctx.Err())
			}
			logger.Error("go list failed", "err", err)
			return nil, fmt.Errorf("failed to list packages: %w", err)
		}

		allPkgs := strings.Split(strings.TrimSpace(string(output)), "\n")
		projectPkgs := make([]string, 0)
		for _, pkg := range allPkgs {
			if strings.HasPrefix(pkg, modulePath) {
				projectPkgs = append(projectPkgs, pkg)
			}
		}
		return projectPkgs, nil
	}
}

type pkgImportsFinder func(projectPath, pkgPath string) ([]string, error)

func newPkgImportsFinder(logger *slog.Logger) pkgImportsFinder {
	return func(projectPath, pkgPath string) ([]string, error) {
		logger.Debug("loading package imports", "package", pkgPath)
		cfg := &packages.Config{
			Mode: packages.NeedImports,
			Dir:  projectPath,
		}

		pkgs, err := packages.Load(cfg, pkgPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load package %s: %w", pkgPath, err)
		}

		if len(pkgs) == 0 {
			return nil, fmt.Errorf("package %s not found", pkgPath)
		}

		imports := make([]string, 0, len(pkgs[0].Imports))
		for imp := range pkgs[0].Imports {
			imports = append(imports, imp)
		}

		return imports, nil
	}
}

type PkgDependenciesFinder interface {
	getAllPkgDependencies(ctx context.Context, projectPath, targetPkg string, allPkgs []string, maxDepth int) ([]string, error)
}

type defaultPkgDependenciesFinder struct {
	logger           *slog.Logger
	pkgImportsFinder pkgImportsFinder
}

func NewPkgDependenciesFinder(logger *slog.Logger) PkgDependenciesFinder {
	return &defaultPkgDependenciesFinder{
		logger:           logger,
		pkgImportsFinder: newPkgImportsFinder(logger),
	}
}

func (pkgDependenciesFinder defaultPkgDependenciesFinder) getAllPkgDependencies(
	ctx context.Context,
	projectPath,
	targetPkg string,
	allPkgs []string,
	maxDepth int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	pkgDependenciesFinder.logger.Info("the process of finding dependent vulnerable packages has begun", "max depth", maxDepth)
	start := time.Now()
	dependencyGrap := pkgDependenciesFinder.getAllPkgsDepsMap(ctx, projectPath, allPkgs)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
	}
	visited := map[string]bool{}
	queue := []struct {
		pkg   string
		depth int
	}{{targetPkg, 0}}
	var results []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth > maxDepth {
			continue
		}
		visited[current.pkg] = true
		for _, dep := range dependencyGrap[current.pkg] {
			if !visited[dep] {
				visited[dep] = true
				results = append(results, dep)
				queue = append(queue, struct {
					pkg   string
					depth int
				}{pkg: dep, depth: current.depth + 1})
			}
		}
	}
	pkgDependenciesFinder.logger.Info("the process of finding dependent vulnerable packages has ended", "elapsed time", time.Since(start))
	return results, nil
}

func (pkgDependenciesFinder defaultPkgDependenciesFinder) getAllPkgsDepsMap(
	ctx context.Context,
	projectPath string,
	allPkgs []string) map[string][]string {

	allPkgsSet := make(map[string]struct{}, len(allPkgs))
	for _, pkg := range allPkgs {
		allPkgsSet[pkg] = struct{}{}
	}

	type result struct {
		imp string
		pkg string
	}

	numWorkers := runtime.NumCPU() * 2
	jobs := make(chan string, len(allPkgs))
	results := make(chan result, len(allPkgs))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for pkg := range jobs {
				select {
				case <-ctx.Done():
					pkgDependenciesFinder.logger.Debug("worker cancelled", "worker", workerID)
					return
				default:
				}

				imports, err := pkgDependenciesFinder.pkgImportsFinder(
					projectPath, pkg)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					pkgDependenciesFinder.logger.Error("failed to imports",
						"pkg", pkg, "err", err)
					continue
				}

				for _, imp := range imports {
					if _, exists := allPkgsSet[imp]; exists {
						select {
						case results <- result{imp: imp, pkg: pkg}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}(i)
	}

	go func() {
		defer close(jobs)
		for _, pkg := range allPkgs {
			select {
			case jobs <- pkg:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	dependencyGraph := make(map[string][]string)

	for res := range results {
		dependencyGraph[res.imp] = append(dependencyGraph[res.imp], res.pkg)
	}

	return dependencyGraph
}
