package xtools

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

func newAllProjectPkgsFinder(logger *slog.Logger) allProjectPkgsFinder {
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
