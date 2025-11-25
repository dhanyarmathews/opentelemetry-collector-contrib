package stratifiedprobabilisticsamplerextension

import (
    "context"
    "log"

    "go.opentelemetry.io/collector/component"
    "go.opentelemetry.io/collector/extension"
)

var (
    Type, _            = component.NewType("stratified_probabilistic_sampler")
    ExtensionStability = component.StabilityLevelAlpha
)

func NewFactory() extension.Factory {
    return extension.NewFactory(
        Type,
        createDefaultConfig,
        createExtension,
        ExtensionStability,
    )
}

func createExtension(
    _ context.Context,
    settings extension.Settings,
    cfg component.Config,
) (extension.Extension, error) {
    return NewExtension(settings, cfg.(*Config))
}

func init() {
    // nothing here; policy registration happens in policy_factory.go
    log.Println("[StratifiedSampler] extension init completed")
}

