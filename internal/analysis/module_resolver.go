package analysis

import (
	"fmt"
	"golang.org/x/mod/modfile"
	"log/slog"
	"os"
	"path/filepath"
)

type defaultModuleResolver struct {
	logger *slog.Logger
}

func newModuleResolver(logger *slog.Logger) modulePathResolver {
	return &defaultModuleResolver{
		logger: logger,
	}
}

func (resolver *defaultModuleResolver) ResolveModulePath(projectPath string) (string, error) {
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
