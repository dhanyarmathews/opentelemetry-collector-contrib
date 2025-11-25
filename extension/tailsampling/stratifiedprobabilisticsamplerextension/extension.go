package stratifiedprobabilisticsamplerextension

import (
    "context"

    "go.opentelemetry.io/collector/component"
    "go.opentelemetry.io/collector/extension"
    "go.uber.org/zap"
)

type StratifiedProbabilisticExtension struct {
    logger *zap.Logger
    cfg    *Config
}

func NewExtension(settings extension.Settings, cfg *Config) (*StratifiedProbabilisticExtension, error) {
    return &StratifiedProbabilisticExtension{
        logger: settings.Logger,
        cfg:    cfg,
    }, nil
}

func (e *StratifiedProbabilisticExtension) Start(_ context.Context, _ component.Host) error {
    e.logger.Info("Stratified Probabilistic Sampler extension started")
    return nil
}

func (e *StratifiedProbabilisticExtension) Shutdown(_ context.Context) error {
    e.logger.Info("Stratified Probabilistic Sampler extension stopped")
    return nil
}

