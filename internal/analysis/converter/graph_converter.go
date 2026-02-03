package converter

import (
	"context"
	"fmt"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type defaultGraphConverter struct {
	logger            *slog.Logger
	allNodesFinder    allNodesFinder
	connectionBuilder connectionBuilder
}

func (c defaultGraphConverter) Convert(
	ctx context.Context,
	callGraph *callgraph.Graph,
	fset *token.FileSet,
	modulePath string,
	vulnFuncInfo *models.VulnFuncInfo,
) (*models.Tree, error) {
	if callGraph == nil {
		return nil, fmt.Errorf("call graph is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	nodeMap := c.allNodesFinder.getAllNodesMap(ctx, callGraph, fset, modulePath)

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	c.connectionBuilder.buildConnections(ctx, callGraph, nodeMap, fset, modulePath)

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	key, target, err := c.getTargetVulnNode(nodeMap, vulnFuncInfo)
	if err != nil {
		return nil, err
	}
	tree := &models.Tree{
		Roots: map[string]*models.TreeNode{
			key: target,
		},
		AllNodes: nodeMap,
	}
	return tree, nil
}

func (c defaultGraphConverter) getTargetVulnNode(nodeMap map[string]*models.TreeNode, vulnFuncInfo *models.VulnFuncInfo) (string, *models.TreeNode, error) {
	key := fmt.Sprintf(models.KeyForNodeStructure, vulnFuncInfo.FuncName, vulnFuncInfo.FileName, vulnFuncInfo.Line)
	target, ok := nodeMap[key]
	if !ok {
		return "", nil, fmt.Errorf("vulnerable function with key %s not found in call graph", key)
	}
	return key, target, nil
}
