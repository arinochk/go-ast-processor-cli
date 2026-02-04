package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type defaultIncomingEdgesAdder struct {
	logger          *slog.Logger
	nodeFilter      nodeFilter
	nodeIdGenerator nodeIdGenerator
}

func newIncomingEdgesAdder(logger *slog.Logger) incomingEdgesAdder {
	return defaultIncomingEdgesAdder{
		logger:          logger,
		nodeFilter:      newNodeFilter(),
		nodeIdGenerator: newNodeIDGenerator(),
	}
}

func (incomingEdgesAdder defaultIncomingEdgesAdder) addIncomingEdge(
	ctx context.Context,
	currentNodeDomain *models.TreeNode,
	currentNode *callgraph.Node,
	nodeMap map[string]*models.TreeNode,
	modulePath string,
	fset *token.FileSet) {

	for _, edge := range currentNode.In {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if edge.Caller == nil || edge.Caller.Func == nil {
			continue
		}

		callerFn := edge.Caller.Func
		if incomingEdgesAdder.nodeFilter(callerFn, edge.Caller, modulePath, fset) {
			continue
		}

		callerId := incomingEdgesAdder.nodeIdGenerator(callerFn, fset)
		if callerNode, exists := nodeMap[callerId]; exists && currentNodeDomain != callerNode {
			callPos := fset.Position(edge.Site.Pos())
			callSite := models.CallFuncInfo{
				CalleePkgPath:  callerFn.Pkg.Pkg.Path(),
				CalleeFileName: callPos.Filename,
				CalleeLine:     callPos.Line,
				CalleeFuncName: currentNode.Func.Name(),
				CalleeColumn:   callPos.Column,
			}
			currentNodeDomain.InNodes[callSite] = callerNode
		}
	}
}
