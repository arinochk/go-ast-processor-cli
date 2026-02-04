package tree

import (
	"context"
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
	FindPath(ctx context.Context, tree *models.Tree, vulnFuncInfo *models.VulnFuncInfo) ([][]*models.TreeNode, error)
}

func NewPathFuncFinder() PathFuncFinder {
	return &PathFuncFinderImpl{}
}

type PathFuncFinderImpl struct {
}

func (f *PathFuncFinderImpl) FindPath(
	ctx context.Context,
	tree *models.Tree,
	vulnFuncInfo *models.VulnFuncInfo) ([][]*models.TreeNode, error) {

	key := fmt.Sprintf(models.KeyForNodeStructure, vulnFuncInfo.FuncName, vulnFuncInfo.FileName, vulnFuncInfo.Line)
	target, ok := tree.AllNodes[key]
	if !ok {
		slog.Error("Failed to find path for node:", vulnFuncInfo.FuncName)
		for k, v := range tree.AllNodes {
			if strings.Contains(v.FuncInfo.Name, vulnFuncInfo.FuncName) {
				slog.Info(fmt.Sprintf("Found path function: %s Key: %s", vulnFuncInfo.FuncName, k))
			}
			if v.FuncInfo.Name == vulnFuncInfo.FuncName {
				slog.Info(fmt.Sprintf("Found path function: %s Key: %s", vulnFuncInfo.FuncName, k))
			}
		}
		return nil, fmt.Errorf("function not found in call graph")
	}

	allPaths := make([][]*models.TreeNode, 0)
	currentPath := make([]*models.TreeNode, 0)
	visitedInCurrentPath := make(map[*models.TreeNode]bool)
	depthCounter := 0

	var dfs func(node *models.TreeNode) error
	dfs = func(node *models.TreeNode) error {
		depthCounter++

		// Проверяем контекст каждые 50 уровней глубины
		if depthCounter%50 == 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("operation cancelled")
			default:
			}
		}

		// Проверяем циклы
		if visitedInCurrentPath[node] {
			return nil
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
				if err := dfs(caller); err != nil {
					return err
				}
			}
		}

		// Backtracking: удаляем узел из текущего пути
		currentPath = currentPath[:len(currentPath)-1]
		delete(visitedInCurrentPath, node)
		depthCounter--
		return nil
	}

	// Запускаем DFS от целевой функции
	if err := dfs(target); err != nil {
		return nil, err
	}
	return allPaths, nil
}
