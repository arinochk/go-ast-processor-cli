package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type OutgoingEdgesAdder interface {
	addOutgoingEdge(ctx context.Context, currentNodeDomain *models.TreeNode,
		currentNode *callgraph.Node, nodeMap map[string]*models.TreeNode,
		modulePath string, fset *token.FileSet)
}

type defaultOutgoingEdgesAdder struct {
	logger          *slog.Logger
	nodeFilter      NodeFilter
	nodeIdGenerator NodeIdGenerator
}

func NewOutgoingEdgesAdder(
	logger *slog.Logger,
	filter NodeFilter,
	generator NodeIdGenerator) OutgoingEdgesAdder {
	return defaultOutgoingEdgesAdder{
		logger:          logger,
		nodeFilter:      filter,
		nodeIdGenerator: generator,
	}
}

func (outEdgeAdder defaultOutgoingEdgesAdder) addOutgoingEdge(
	ctx context.Context,
	currentNodeDto *models.TreeNode,
	currentNode *callgraph.Node,
	nodeMap map[string]*models.TreeNode,
	modulePath string,
	fset *token.FileSet) {
	for _, edge := range currentNode.Out {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if edge.Callee == nil || edge.Callee.Func == nil {
			continue
		}

		calleeFn := edge.Callee.Func
		if outEdgeAdder.nodeFilter(calleeFn, edge.Callee, modulePath, fset) {
			continue
		}

		calleeId := outEdgeAdder.nodeIdGenerator(calleeFn, fset)
		if calleeNode, exists := nodeMap[calleeId]; exists && currentNodeDto != calleeNode {
			callPos := fset.Position(edge.Site.Pos())

			callSite := models.CallFuncInfo{
				CalleePkgPath:  currentNode.Func.Pkg.Pkg.Path(),
				CalleeFileName: callPos.Filename,
				CalleeLine:     callPos.Line,
				CalleeFuncName: calleeFn.Name(),
				CalleeColumn:   callPos.Column,
			}

			currentNodeDto.OutNodes[callSite] = calleeNode
		}
	}
}
