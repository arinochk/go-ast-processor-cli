package xtools

import (
	"context"
	"fmt"
	"log/slog"
)

type defaultVulnPkgsFinder struct {
	logger                *slog.Logger
	pkgByFilePathFinder   pkgByFilePathFinder
	allProjectPkgsFinder  allProjectPkgsFinder
	pkgDependenciesFinder pkgDependenciesFinder
}

func newVulnPkgsFinder(logger *slog.Logger) vulnPkgsFinder {
	return &defaultVulnPkgsFinder{
		logger:                logger,
		pkgByFilePathFinder:   newPkgByFilePathFinder(logger),
		allProjectPkgsFinder:  newAllProjectPkgsFinder(logger),
		pkgDependenciesFinder: newPkgDependenciesFinder(logger),
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
