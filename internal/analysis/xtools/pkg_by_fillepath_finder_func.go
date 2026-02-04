package xtools

import (
	"context"
	"fmt"
	"golang.org/x/tools/go/packages"
	"log/slog"
	"os"
)

func newPkgByFilePathFinder(logger *slog.Logger) pkgByFilePathFinder {
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
