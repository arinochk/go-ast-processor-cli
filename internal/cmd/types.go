package cmd

import (
	"go-ast-processor-cli/internal/models"
)

type OutputProcessor interface {
	Process(functionCallPaths [][]*models.TreeNode)
}

type writer interface {
	write(functionCallPaths [][]*models.TreeNode)
}
