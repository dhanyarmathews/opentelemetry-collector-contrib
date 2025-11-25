package spanintentprocessor

import (
    "context"
    "time"

    "go.opentelemetry.io/collector/component"
    "go.opentelemetry.io/collector/consumer"
    "go.opentelemetry.io/collector/processor"

    "github.com/open-telemetry/opentelemetry-collector-contrib/processor/spanintentprocessor/internal/metadata"
)

const typeStr = "spanintentprocessor"

func NewFactory() processor.Factory {
    return processor.NewFactory(
        component.MustNewType(typeStr), // convert here, NOT in const
        createDefaultConfig,
        processor.WithTraces(createTracesProcessor, metadata.TracesStability),
    )
}

func createDefaultConfig() component.Config {
    return &Config{
        TickInterval:       10 * time.Second,
        SamplingPercentage: 0.3,
        SamplingBias: SamplingBias{
            Normal:   0.3,
            Degraded: 1.0,
            Failed:   1.0,
        },
        SampledTracesCacheSize:   10000,
        UnsampledTracesCacheSize: 10000,
    }
}

func createTracesProcessor(
    ctx context.Context,
    params processor.Settings,
    cfg component.Config,
    nextConsumer consumer.Traces,
) (processor.Traces, error) {
    tCfg := cfg.(*Config)
    return newSpanIntentProcessor(params.Logger, tCfg, nextConsumer)
}

