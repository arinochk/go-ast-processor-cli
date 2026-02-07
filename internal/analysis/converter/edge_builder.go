package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"log/slog"
)

type ConnectionBuilder interface {
	buildConnections(ctx context.Context, callGraph *callgraph.Graph,
		nodeMap map[string]*models.TreeNode, fset *token.FileSet, modulePath string)
}

type edgeBuilder struct {
	logger          *slog.Logger
	nodeFilter      NodeFilter
	nodeIdGenerator NodeIdGenerator
	edgesAdder      EdgesAdder
}

func NewConnectionBuilder(
	logger *slog.Logger,
	nodeFilter NodeFilter,
	nodeIdGenerator NodeIdGenerator,
	edgesAdder EdgesAdder) ConnectionBuilder {
	return &edgeBuilder{
		logger:          logger,
		nodeFilter:      nodeFilter,
		nodeIdGenerator: nodeIdGenerator,
		edgesAdder:      edgesAdder,
	}
}

func (edgeBuilder edgeBuilder) buildConnections(
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

		edgeBuilder.edgesAdder.addOutgoingEdge(ctx, currentNodeDomain, node, nodeMap, modulePath, fset)
		edgeBuilder.edgesAdder.addIncomingEdge(ctx, currentNodeDomain, node, nodeMap, modulePath, fset)
	}
}
