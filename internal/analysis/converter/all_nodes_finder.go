package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type AllNodesFinder interface {
	getAllNodesMap(ctx context.Context, callGraph *callgraph.Graph,
		fset *token.FileSet, modulePath string) map[string]*models.TreeNode
}

type defaultAllNodesFinder struct {
	logger            *slog.Logger
	nodeFilter        NodeFilter
	funcIdGenerator   NodeIdGenerator
	ssaFunctionMapper SsaFunctionMapper
}

func NewAllNodesFinder(
	logger *slog.Logger,
	filter NodeFilter,
	generator NodeIdGenerator,
	mapper SsaFunctionMapper) AllNodesFinder {
	return &defaultAllNodesFinder{
		logger:            logger,
		nodeFilter:        filter,
		funcIdGenerator:   generator,
		ssaFunctionMapper: mapper,
	}
}

func (nodesFinder defaultAllNodesFinder) getAllNodesMap(
	ctx context.Context,
	callGraph *callgraph.Graph,
	fset *token.FileSet,
	modulePath string) map[string]*models.TreeNode {

	nodeMap := make(map[string]*models.TreeNode)

	for _, node := range callGraph.Nodes {

		select {
		case <-ctx.Done():
			return nodeMap
		default:
		}

		if nodesFinder.nodeFilter(node.Func, node, modulePath, fset) {
			continue
		}

		funcInfo := nodesFinder.ssaFunctionMapper(node.Func, fset)
		funcId := nodesFinder.funcIdGenerator(node.Func, fset)

		if _, exists := nodeMap[funcId]; !exists {
			nodeMap[funcId] = &models.TreeNode{
				FuncInfo: funcInfo,
				InNodes:  make(map[models.CallFuncInfo]*models.TreeNode),
				OutNodes: make(map[models.CallFuncInfo]*models.TreeNode),
			}
		}
	}

	return nodeMap
}
