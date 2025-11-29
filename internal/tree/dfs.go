package tree

import (
	"fmt"
	"go-ast-processor-cli/internal/models"
	"log/slog"
	"strings"
)

/*
Нужно в карте функций найти узел по пакету и названию
Для найденного узла пройтись алгоритмом DFS и вывести все возможные пути
Мы ищем путь до корневых узлов.
*/
type PathFuncFinder interface {
	FindPath(pkgPath string, funcName string, filename string, line int) ([][]*models.TreeNode, error)
}

func NewPathFuncFinder(tree *models.Tree) PathFuncFinder {
	return &PathFuncFinderImpl{Tree: tree}
}

type PathFuncFinderImpl struct {
	Tree *models.Tree
}

func (f *PathFuncFinderImpl) FindPath(pkgPath string, funcName string, filename string, line int) ([][]*models.TreeNode, error) {
	key := fmt.Sprintf(models.KeyForNodeStructure, pkgPath, funcName, filename, line)
	target, ok := f.Tree.AllNodes[key]
	if !ok {
		slog.Error("Failed to find path for node:", pkgPath, funcName)
		for k, v := range f.Tree.AllNodes {
			if k == pkgPath {
				slog.Info(fmt.Sprintf("Found package path for: %s", pkgPath))
			}
			if strings.Contains(v.FuncInfo.Name, funcName) {
				slog.Info(fmt.Sprintf("Found path function: %s Key: %s", funcName, k))
			}
			if v.FuncInfo.Name == funcName {
				slog.Info(fmt.Sprintf("Found path function: %s Key: %s", funcName, k))
			}
		}
		return nil, fmt.Errorf("function not found in call graph")
	}

	allPaths := make([][]*models.TreeNode, 0)
	currentPath := make([]*models.TreeNode, 0)
	visitedInCurrentPath := make(map[*models.TreeNode]bool)

	var dfs func(node *models.TreeNode)
	dfs = func(node *models.TreeNode) {
		// Проверяем циклы
		if visitedInCurrentPath[node] {
			return
		}

		// Добавляем узел в текущий путь
		currentPath = append(currentPath, node)
		visitedInCurrentPath[node] = true

		// Если достигли корня (функции, которую никто не вызывает)
		if len(node.InNodes) == 0 {
			// Сохраняем копию пути
			pathCopy := make([]*models.TreeNode, len(currentPath))
			copy(pathCopy, currentPath)
			allPaths = append(allPaths, pathCopy)
		} else {
			// Рекурсивно обходим всех вызывающих (InNodes)
			for _, caller := range node.InNodes {
				dfs(caller)
			}
		}

		// Backtracking: удаляем узел из текущего пути
		currentPath = currentPath[:len(currentPath)-1]
		delete(visitedInCurrentPath, node)
	}

	// Запускаем DFS от целевой функции
	dfs(target)
	return allPaths, nil
}
