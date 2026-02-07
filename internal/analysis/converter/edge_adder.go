package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type EdgesAdder interface {
	addIncomingEdge(ctx context.Context, currentNodeDomain *models.TreeNode,
		currentNode *callgraph.Node, nodeMap map[string]*models.TreeNode,
		modulePath string, fset *token.FileSet)

	addOutgoingEdge(ctx context.Context, currentNodeDomain *models.TreeNode,
		currentNode *callgraph.Node, nodeMap map[string]*models.TreeNode,
		modulePath string, fset *token.FileSet)
}

type edgeAdder struct {
	logger          *slog.Logger
	nodeFilter      NodeFilter
	nodeIdGenerator NodeIdGenerator
}

func NewEdgesAdder(logger *slog.Logger,
	nodeFilter NodeFilter,
	nodeIdGenerator NodeIdGenerator) EdgesAdder {
	return edgeAdder{
		logger:          logger,
		nodeFilter:      nodeFilter,
		nodeIdGenerator: nodeIdGenerator,
	}
}

func (edgeAdder edgeAdder) addIncomingEdge(
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
		if edgeAdder.nodeFilter(callerFn, edge.Caller, modulePath, fset) {
			continue
		}

		callerId := edgeAdder.nodeIdGenerator(callerFn, fset)
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

func (edgeAdder edgeAdder) addOutgoingEdge(
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
		if edgeAdder.nodeFilter(calleeFn, edge.Callee, modulePath, fset) {
			continue
		}

		calleeId := edgeAdder.nodeIdGenerator(calleeFn, fset)
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
