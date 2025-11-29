package analysis

import (
	"fmt"
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"strings"
)

type CallGraphToDtoConverter interface {
	ConvertToDto() (*models.Tree, error)
}

func NewGraphToDtoConverter(representation *AnalyzerResult) CallGraphToDtoConverter {
	return &commonConverter{representation: representation}
}

type commonConverter struct {
	representation *AnalyzerResult
}

func (c *commonConverter) ConvertToDto() (*models.Tree, error) {
	callGraph := c.representation.CallGraph
	fset := c.representation.Fset
	modulePath := c.representation.ModulePath

	if callGraph == nil {
		return nil, fmt.Errorf("call graph is nil")
	}

	// Создаем все узлы
	nodeMap := c.getAllNodesMap(callGraph, fset, modulePath)

	// Строим связи
	c.buildConnections(callGraph, nodeMap, fset, modulePath)

	// Находим корни (функции без вызывающих)
	tree := &models.Tree{
		Roots:    make(map[string]*models.TreeNode),
		AllNodes: nodeMap,
	}
	for funcId, node := range nodeMap {
		if len(node.InNodes) == 0 {
			tree.Roots[funcId] = node
		}
	}

	return tree, nil
}

func (c *commonConverter) getAllNodesMap(
	callGraph *callgraph.Graph,
	fset *token.FileSet,
	modulePath string,
) map[string]*models.TreeNode {
	nodeMap := make(map[string]*models.TreeNode)

	for _, node := range callGraph.Nodes {
		if c.shouldSkipNode(node.Func, node, modulePath, fset) {
			continue
		}

		funcInfo := c.convertSsaFuncToModel(node.Func, fset)
		funcId := c.generateFunctionID(node.Func, fset)

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

func (c *commonConverter) buildConnections(
	callGraph *callgraph.Graph,
	nodeMap map[string]*models.TreeNode,
	fset *token.FileSet,
	modulePath string,
) {
	for _, node := range callGraph.Nodes {
		if c.shouldSkipNode(node.Func, node, modulePath, fset) {
			continue
		}

		funcId := c.generateFunctionID(node.Func, fset)
		currentNode, exists := nodeMap[funcId]
		if !exists {
			continue
		}

		// Обрабатываем исходящие вызовы
		for _, edge := range node.Out {
			if edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}

			calleeFn := edge.Callee.Func
			if c.shouldSkipNode(calleeFn, edge.Callee, modulePath, fset) {
				continue
			}

			calleeId := c.generateFunctionID(calleeFn, fset)
			if calleeNode, exists := nodeMap[calleeId]; exists && currentNode != calleeNode {
				callSite := c.createCallSiteInfo(edge.Site, fset, node.Func, calleeFn.Name())
				currentNode.OutNodes[callSite] = calleeNode
			}
		}

		// Обрабатываем входящие вызовы
		for _, edge := range node.In {
			if edge.Caller == nil || edge.Caller.Func == nil {
				continue
			}

			callerFn := edge.Caller.Func
			if c.shouldSkipNode(callerFn, edge.Caller, modulePath, fset) {
				continue
			}

			callerId := c.generateFunctionID(callerFn, fset)
			if callerNode, exists := nodeMap[callerId]; exists && currentNode != callerNode {
				callSite := c.createCallSiteInfo(edge.Site, fset, callerFn, node.Func.Name())
				currentNode.InNodes[callSite] = callerNode
			}
		}
	}
}

func (c *commonConverter) shouldSkipNode(fn *ssa.Function, node *callgraph.Node, modulePath string, fset *token.FileSet) bool {
	if fn == nil || node == nil || node.Func == nil || node.Func.Pkg == nil || node.Func.Pkg.Pkg == nil {
		return true
	}

	pkgPath := node.Func.Pkg.Pkg.Path()
	if !strings.HasPrefix(pkgPath, modulePath) {
		return true
	}

	position := fset.Position(fn.Pos())
	if !position.IsValid() {
		return true
	}

	// Пропускаем init функции
	if node.Func.Name() == "init" {
		return true
	}

	return false
}

func (c *commonConverter) createCallSiteInfo(site ssa.CallInstruction, fset *token.FileSet, fn *ssa.Function, calledFuncName string) models.CallFuncInfo {
	callPos := fset.Position(site.Pos())

	return models.CallFuncInfo{
		CalleePkgPath:  fn.Pkg.Pkg.Path(),
		CalleeFileName: callPos.Filename,
		CalleeLine:     callPos.Line,
		CalleeFuncName: calledFuncName,
		CalleeColumn:   callPos.Column,
	}
}

func (c *commonConverter) generateFunctionID(fn *ssa.Function, fset *token.FileSet) string {
	funcPos := fset.Position(fn.Pos())
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fmt.Sprintf(models.KeyForNodeStructure, fn.Pkg.Pkg.Path(), fn.Name(), funcPos.Filename, funcPos.Line)
	}
	return fn.Name()
}

func (c *commonConverter) convertSsaFuncToModel(fn *ssa.Function, fset *token.FileSet) *models.FuncInfo {
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
