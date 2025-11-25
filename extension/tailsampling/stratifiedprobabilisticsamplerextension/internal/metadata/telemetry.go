package metadata

import (
    "go.opentelemetry.io/collector/component"
    "go.uber.org/zap"
)

type TelemetryBuilder struct {
    Logger *zap.Logger
}

func NewTelemetryBuilder(settings component.TelemetrySettings) (*TelemetryBuilder, error) {
    return &TelemetryBuilder{Logger: settings.Logger}, nil
}

