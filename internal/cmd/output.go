package cmd

import (
	"fmt"
	"go-ast-processor-cli/internal/models"
	"log/slog"
	"strings"
)

type OutputProcessor interface {
	Process(functionCallPaths [][]*models.TreeNode)
}

type defaultOutputProcessor struct {
	writer writer
}

func NewOuputProcessor() OutputProcessor {
	return &defaultOutputProcessor{
		writer: newConsoleWriter(),
	}
}

func (outputProcessor defaultOutputProcessor) Process(functionCallPaths [][]*models.TreeNode) {
	outputProcessor.writer.write(functionCallPaths)
}

type writer interface {
	write(functionCallPaths [][]*models.TreeNode)
}

type consoleWriter struct {
}

func newConsoleWriter() writer {
	return consoleWriter{}
}

func (c consoleWriter) write(functionCallPaths [][]*models.TreeNode) {
	if len(functionCallPaths) == 0 {
		slog.Info("No call paths found for the target function")
		return
	}

	slog.Info(fmt.Sprintf("Found %d call path(s):", len(functionCallPaths)))
	for i, path := range functionCallPaths {
		slog.Info(fmt.Sprintf("Path %d:", i+1))

		// Путь хранится в порядке от вызывающих к целевой функции
		// Разворачиваем для более естественного отображения
		for j := len(path) - 1; j >= 0; j-- {
			node := path[j]
			if node.FuncInfo != nil {
				callerInfo := fmt.Sprintf("  → %s.%s",
					node.FuncInfo.PkgPath,
					node.FuncInfo.Name)

				if node.FuncInfo.FileName != "" {
					callerInfo += fmt.Sprintf(" (file: %s", node.FuncInfo.FileName)
					if node.FuncInfo.Line > 0 {
						callerInfo += fmt.Sprintf(", line: %d", node.FuncInfo.Line)
					}
					callerInfo += ")"
				}

				slog.Info(callerInfo)
			}
		}
		slog.Info(strings.Repeat("-", 50))
	}
}

// TODO: добавить поддержку записи JSON
type jsonWriter struct{}
