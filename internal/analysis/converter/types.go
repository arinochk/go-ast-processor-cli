package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

type GraphConverter interface {
	Convert(ctx context.Context, callGraph *callgraph.Graph, fset *token.FileSet,
		modulePath string, vulnFuncInfo *models.VulnFuncInfo) (*models.Tree, error)
}

type allNodesFinder interface {
	getAllNodesMap(ctx context.Context, callGraph *callgraph.Graph,
		fset *token.FileSet, modulePath string) map[string]*models.TreeNode
}

type connectionBuilder interface {
	buildConnections(ctx context.Context, callGraph *callgraph.Graph,
		nodeMap map[string]*models.TreeNode, fset *token.FileSet, modulePath string)
}

type outgoingEdgesAdder interface {
	addOutgoingEdge(ctx context.Context, currentNodeDomain *models.TreeNode,
		currentNode *callgraph.Node, nodeMap map[string]*models.TreeNode,
		modulePath string, fset *token.FileSet)
}

type incomingEdgesAdder interface {
	addIncomingEdge(ctx context.Context, currentNodeDomain *models.TreeNode,
		currentNode *callgraph.Node, nodeMap map[string]*models.TreeNode,
		modulePath string, fset *token.FileSet)
}
type nodeFilter func(fn *ssa.Function, node *callgraph.Node, modulePath string, fset *token.FileSet) bool

type nodeIdGenerator func(fn *ssa.Function, fset *token.FileSet) string

type ssaFunctionMapper func(fn *ssa.Function, fset *token.FileSet) *models.FuncInfo
