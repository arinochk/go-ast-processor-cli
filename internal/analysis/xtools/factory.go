package xtools

import "log/slog"

func NewGraphBuilder(
	logger *slog.Logger,
	builder SsaBuilder,
	filter GraphFilter) GraphBuilder {
	return &defaultGraphBuilder{
		ssaBuilder:  builder,
		graphFilter: filter,
		logger:      logger,
	}
}
