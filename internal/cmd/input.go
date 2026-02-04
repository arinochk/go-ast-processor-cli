package cmd

import (
	"bufio"
	"fmt"
	"go-ast-processor-cli/internal/models"
	"go-ast-processor-cli/internal/utils"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type InputProcessor interface {
	ProcessProjectPathInput() (string, error)
	ProcessTargetFunctionInput() (*models.VulnFuncInfo, error)
}

func NewCliProcessor(logger *slog.Logger) InputProcessor {
	return &defaultInputProcessor{
		logger: logger,
	}
}

type defaultInputProcessor struct {
	logger *slog.Logger
}

func (processor *defaultInputProcessor) ProcessProjectPathInput() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	var projectDir string
	processor.logger.Info("go-ast-processor started")
	processor.logger.Info("Enter the path to the directory for analysis")

	projectDir, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error scanning directory: %w", err)
	}

	projectDir = strings.TrimSpace(projectDir)

	if projectDir == "" {
		return "", fmt.Errorf("no project directory provided")
	}

	dirExists, err := utils.IsDirectoryExist(projectDir)
	if err != nil {
		return "", fmt.Errorf("error checking directory: %w", err)
	}

	if !dirExists {
		return "", fmt.Errorf("project directory does not exist: %s", projectDir)
	}

	processor.logger.Info("Project directory validated", "path", projectDir)

	return projectDir, nil
}

func (processor *defaultInputProcessor) ProcessTargetFunctionInput() (*models.VulnFuncInfo, error) {
	reader := bufio.NewReader(os.Stdin)

	processor.logger.Info("Enter the function name:")
	functionName, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("error reading function name", "error", err)
		return nil, fmt.Errorf("error reading function name: %w", err)
	}
	functionName = strings.TrimSpace(functionName)

	processor.logger.Info("Enter the whole path for file for function:")
	fileName, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("error reading path to file", "error", err)
		return nil, fmt.Errorf("error reading function name: %w", err)
	}
	fileName = strings.TrimSpace(fileName)

	processor.logger.Info("Enter the function function line:")
	lineStr, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("error reading function line", "error", err)
	}
	lineStr = strings.TrimSpace(lineStr)
	line, err := strconv.Atoi(lineStr)
	if err != nil {
		slog.Error("error converting function line", "error", err)
	}

	if functionName == "" || fileName == "" {
		return nil, fmt.Errorf("package path and function name cannot be empty")
	}

	processor.logger.Info("Target function", "function", functionName)
	return &models.VulnFuncInfo{
		FuncName: functionName,
		FileName: fileName,
		Line:     line,
	}, nil
}
