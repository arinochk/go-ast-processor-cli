package xtools

import "log/slog"

func NewGraphBuilder(logger *slog.Logger) GraphBuilder {
	return &defaultGraphBuilder{
		ssaBuilder:  newSsaBuilder(logger),
		graphFilter: newGraphFilter(),
		logger:      logger,
	}
}
