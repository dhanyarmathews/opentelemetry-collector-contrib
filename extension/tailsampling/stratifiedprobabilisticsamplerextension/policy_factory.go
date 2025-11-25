package stratifiedprobabilisticsamplerextension

import (
    "go.uber.org/zap"

    //"github.com/open-telemetry/opentelemetry-collector-contrib/processor/tailsamplingprocessor/internal/policy"
    "github.com/open-telemetry/opentelemetry-collector-contrib/processor/tailsamplingprocessor/pkg/samplingpolicy"
)

type StratifiedPolicyFactory struct{}

func (StratifiedPolicyFactory) Create(cfg map[string]any, logger *zap.Logger) (samplingpolicy.Evaluator, error) {

    samplingPercent := 100.0
    if raw, ok := cfg["sampling_percentage"].(float64); ok {
        samplingPercent = raw
    }

    return &StratifiedProbabilisticEvaluator{
        logger:               logger,
        threshold:            stratifiedCalculateThreshold(samplingPercent / 100),
        traceTrajectoryCount: map[string]int{},
    }, nil
}

// 🎯 REQUIRED — this is what makes the processor recognize your policy type
/*func init() {
    policy.Register("stratified_probabilistic_sampler", StratifiedPolicyFactory{})
}*/

func init() {
    samplingpolicy.RegisterPolicy("stratified_probabilistic_sampler", StratifiedPolicyFactory{})
}
