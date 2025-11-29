package cmd

import (
	"bufio"
	"fmt"
	"go-ast-processor-cli/internal/fileproc"
	"go-ast-processor-cli/internal/models"
	"golang.org/x/tools/go/packages"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type InputProcessor interface {
	ProcessAnalysisConfInput() (*models.AppConfig, error)
	ProcessTargetFunctionInput() (string, string, string, int, error)
}

func NewCliProcessor() InputProcessor {
	return &cliProcessor{}
}

type cliProcessor struct {
}

func (c *cliProcessor) ProcessAnalysisConfInput() (*models.AppConfig, error) {
	reader := bufio.NewReader(os.Stdin)

	var projectDir string
	slog.Info("go-ast-processor started")
	slog.Info("Enter the path to the directory for analysis")

	projectDir, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("error scanning directory: %w", err)
	}

	projectDir = strings.TrimSpace(projectDir)

	if projectDir == "" {
		return nil, fmt.Errorf("no project directory provided")
	}

	dirExists, err := fileproc.IsDirectoryExist(projectDir)
	if err != nil {
		return nil, fmt.Errorf("error checking directory: %w", err)
	}

	if !dirExists {
		return nil, fmt.Errorf("project directory does not exist: %s", projectDir)
	}

	slog.Info("Project directory validated", "path", projectDir)

	return &models.AppConfig{
		Config: &packages.Config{
			Dir:  projectDir,
			Mode: packages.LoadAllSyntax,
		},
	}, nil
}

func (c *cliProcessor) ProcessTargetFunctionInput() (string, string, string, int, error) {
	reader := bufio.NewReader(os.Stdin)

	slog.Info("Enter the package path for the target function (e.g., github.com/user/project/pkg):")
	pkgPath, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("error reading package path", "error", err)
		return "", "", "", 0, fmt.Errorf("error reading package path: %w", err)
	}
	pkgPath = strings.TrimSpace(pkgPath)

	slog.Info("Enter the function name:")
	functionName, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("error reading function name", "error", err)
		return "", "", "", 0, fmt.Errorf("error reading function name: %w", err)
	}
	functionName = strings.TrimSpace(functionName)

	slog.Info("Enter the whole path for file for function:")
	fileName, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("error reading path to file", "error", err)
		return "", "", "", 0, fmt.Errorf("error reading function name: %w", err)
	}
	fileName = strings.TrimSpace(fileName)

	slog.Info("Enter the function function line:")
	lineStr, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("error reading function line", "error", err)
	}
	lineStr = strings.TrimSpace(lineStr)
	line, err := strconv.Atoi(lineStr)
	if err != nil {
		slog.Error("error converting function line", "error", err)
	}

	if pkgPath == "" || functionName == "" || fileName == "" {
		return "", "", "", 0, fmt.Errorf("package path and function name cannot be empty")
	}

	slog.Info("Target function", "package", pkgPath, "function", functionName)
	return pkgPath, functionName, fileName, line, nil
}
