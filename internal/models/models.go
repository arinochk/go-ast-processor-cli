package models

type AppConfig struct {
	ProjectPath string
	VulnFunc    *VulnFuncInfo
}

type VulnFuncInfo struct {
	FuncName string
	FileName string
	Line     int
}

/* Структура ключа: путь_до_пакета.название_функции.название_файла.номер_строки */
const KeyForNodeStructure = "{%s}.{%s}.{%d}"

type FuncInfo struct {
	FullSignature string
	FileName      string
	PkgPath       string
	Line          int
	Name          string
	Params        []*ParamInfo
	FileContent   []string
}

type ParamInfo struct {
	Name string
	Type string
}

type TreeNode struct {
	FuncInfo *FuncInfo
	InNodes  map[CallFuncInfo]*TreeNode
	OutNodes map[CallFuncInfo]*TreeNode
}

type Tree struct {
	AllNodes map[string]*TreeNode
	Roots    map[string]*TreeNode
}

type CallFuncInfo struct {
	CalleePkgPath  string
	CalleeFileName string
	CalleeLine     int
	CalleeFuncName string
	CalleeColumn   int
}
