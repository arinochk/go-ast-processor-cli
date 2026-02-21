package xtools

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/analysis/pkgproc"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log/slog"
	"time"
)

type SsaBuilder interface {
	build(ctx context.Context, projectPath, filePath, modulePath string) (*ssa.Program, error)
}

type defaultSsaBuilder struct {
	logger         *slog.Logger
	vulnPkgsFinder pkgproc.VulnPkgsFinder
}

func NewSsaBuilder(logger *slog.Logger,
	vulnPkgsFinder pkgproc.VulnPkgsFinder) SsaBuilder {
	return &defaultSsaBuilder{
		logger:         logger,
		vulnPkgsFinder: vulnPkgsFinder,
	}
}

func (b *defaultSsaBuilder) build(ctx context.Context, projectPath, filePath, modulePath string) (*ssa.Program, error) {
	b.logger.Info("Loading packages for SSA",
		"project", projectPath, "file", filePath)
	start := time.Now()

	pkgsPaths, err := b.vulnPkgsFinder.FindVulnPackages(ctx, projectPath, filePath, modulePath)
	if err != nil {
		return nil, fmt.Errorf("error while finding vulnerable packages: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	if len(pkgsPaths) == 0 {
		return nil, fmt.Errorf("no vulnerable packages found for file: %s", filePath)
	}

	b.logger.Info("Target packages for analysis",
		"count", len(pkgsPaths), "packages", pkgsPaths)
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Dir:   projectPath,
		Tests: false,
	}

	initialPkgs, err := packages.Load(cfg, pkgsPaths...)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	prog, _ := ssautil.Packages(initialPkgs, ssa.BuilderMode(0))
	prog.Build()
	b.logger.Info("Analysis complete", "duration", time.Since(start))
	return prog, nil
}
