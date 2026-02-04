package converter

import "log/slog"

func NewGraphConverter(logger *slog.Logger) GraphConverter {
	return &defaultGraphConverter{
		logger:            logger,
		allNodesFinder:    newAllNodesFinder(logger),
		connectionBuilder: newConnectionBuilder(logger),
	}
}
