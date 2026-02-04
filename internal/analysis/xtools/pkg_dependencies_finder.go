package xtools

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

type defaultPkgDependenciesFinder struct {
	logger           *slog.Logger
	pkgImportsFinder pkgImportsFinder
}

func newPkgDependenciesFinder(logger *slog.Logger) pkgDependenciesFinder {
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
