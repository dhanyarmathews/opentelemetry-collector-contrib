package metadata

import "go.opentelemetry.io/collector/component"


var (
    ProcessorType = component.MustNewType("spanintentprocessor")
    Stability     = component.StabilityLevelAlpha
)

