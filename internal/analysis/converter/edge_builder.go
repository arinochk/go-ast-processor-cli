package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type defaultEdgeBuilder struct {
	logger             *slog.Logger
	nodeFilter         nodeFilter
	nodeIdGenerator    nodeIdGenerator
	outgoingEdgesAdder outgoingEdgesAdder
	incomingEdgesAdder incomingEdgesAdder
}

func newConnectionBuilder(logger *slog.Logger) connectionBuilder {
	return &defaultEdgeBuilder{
		logger:             logger,
		nodeFilter:         newNodeFilter(),
		nodeIdGenerator:    newNodeIDGenerator(),
		outgoingEdgesAdder: newOutgoingEdgesAdder(logger),
		incomingEdgesAdder: newIncomingEdgesAdder(logger),
	}
}

func (edgeBuilder defaultEdgeBuilder) buildConnections(
	ctx context.Context,
	callGraph *callgraph.Graph,
	nodeMap map[string]*models.TreeNode,
	fset *token.FileSet,
	modulePath string) {
	for _, node := range callGraph.Nodes {

		select {
		case <-ctx.Done():
			return
		default:
		}

		if edgeBuilder.nodeFilter(node.Func, node, modulePath, fset) {
			continue
		}

		funcId := edgeBuilder.nodeIdGenerator(node.Func, fset)
		currentNodeDomain, exists := nodeMap[funcId]
		if !exists {
			continue
		}

		edgeBuilder.outgoingEdgesAdder.addOutgoingEdge(ctx, currentNodeDomain, node, nodeMap, modulePath, fset)
		edgeBuilder.incomingEdgesAdder.addIncomingEdge(ctx, currentNodeDomain, node, nodeMap, modulePath, fset)
	}
}
