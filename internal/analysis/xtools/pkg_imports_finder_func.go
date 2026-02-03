package xtools

import (
	"fmt"
	"golang.org/x/tools/go/packages"
	"log/slog"
)

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
