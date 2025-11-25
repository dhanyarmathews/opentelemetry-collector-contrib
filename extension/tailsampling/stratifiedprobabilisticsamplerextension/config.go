package stratifiedprobabilisticsamplerextension

import (
    "go.opentelemetry.io/collector/component"
)

type Config struct {
    SamplingPercentage float64 `mapstructure:"sampling_percentage"`
}

func createDefaultConfig() component.Config {
    return &Config{
        SamplingPercentage: 100,
    }
}

