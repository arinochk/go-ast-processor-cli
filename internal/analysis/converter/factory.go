package converter

import "log/slog"

func NewGraphConverter(
	logger *slog.Logger,
	finder AllNodesFinder,
	builder ConnectionBuilder,
) GraphConverter {
	return &defaultGraphConverter{
		logger:            logger,
		allNodesFinder:    finder,
		connectionBuilder: builder,
	}
}
