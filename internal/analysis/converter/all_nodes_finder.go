package converter

import (
	"context"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"log/slog"
)

type AllNodesFinder interface {
	getAllNodesMap(ctx context.Context, callGraph *callgraph.Graph,
		fset *token.FileSet, modulePath string) map[string]*models.TreeNode
}

type allNodesFinder struct {
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
	return &allNodesFinder{
		logger:            logger,
		nodeFilter:        filter,
		funcIdGenerator:   generator,
		ssaFunctionMapper: mapper,
	}
}

func (nodesFinder allNodesFinder) getAllNodesMap(
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

type SsaFunctionMapper func(fn *ssa.Function, fset *token.FileSet) *models.FuncInfo

func NewSsaFunctionMapper() SsaFunctionMapper {
	return func(fn *ssa.Function, fset *token.FileSet) *models.FuncInfo {
		pos := fset.Position(fn.Pos())

		funcInfo := &models.FuncInfo{
			Name:          fn.Name(),
			PkgPath:       fn.Pkg.Pkg.Path(),
			FileName:      pos.Filename,
			Line:          pos.Line,
			FullSignature: fn.String(),
			Params:        make([]*models.ParamInfo, 0),
		}

		if fn.Signature != nil {
			params := fn.Signature.Params()
			if params != nil {
				for i := 0; i < params.Len(); i++ {
					param := params.At(i)
					paramInfo := &models.ParamInfo{
						Name: param.Name(),
						Type: param.Type().String(),
					}
					funcInfo.Params = append(funcInfo.Params, paramInfo)
				}
			}
		}

		return funcInfo
	}
}
