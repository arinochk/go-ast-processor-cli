package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type defaultOutgoingEdgesAdder struct {
	logger          *slog.Logger
	nodeFilter      nodeFilter
	nodeIdGenerator nodeIdGenerator
}

func newOutgoingEdgesAdder(logger *slog.Logger) outgoingEdgesAdder {
	return defaultOutgoingEdgesAdder{
		logger:          logger,
		nodeFilter:      newNodeFilter(),
		nodeIdGenerator: newNodeIDGenerator(),
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
