package converter

import (
	"go-ast-processor-cli/internal/models"
	"go/token"
	"golang.org/x/tools/go/ssa"
)

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
