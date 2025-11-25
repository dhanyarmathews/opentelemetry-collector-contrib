package spanintentprocessor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestSpanIntentProcessor_Sampling(t *testing.T) {
	cfg := &Config{
		SamplingPercentage: 0.3,
		SamplingBias: SamplingBias{
			Normal:   0.3,
			Degraded: 1.0,
			Failed:   1.0,
		},
	}

	settings := processortest.NewNopSettings()
	nextConsumer := &consumertest.TracesSink{}

	processor, err := newTracesProcessor(context.Background(), settings, cfg, nextConsumer)
	require.NoError(t, err)
	require.NotNil(t, processor)

	err = processor.Start(context.Background(), componenttest.NewNopHost())
	require.NoError(t, err)

	// Provide test data
	traces := generateTracesWithIntent("degraded") // you’ll need to write this generator
	err = processor.ConsumeTraces(context.Background(), traces)
	require.NoError(t, err)

	assert.Len(t, nextConsumer.AllTraces(), 1, "Expected 100% sampling for degraded")
}

func TestSpanIntentProcessor_Metrics(t *testing.T) {
	// Initialize test telemetry setup
	s := setupTestTelemetry()
	cfg := &Config{
		SamplingPercentage: 0.5,
		SamplingBias: SamplingBias{
			Normal:   0.3,
			Degraded: 1.0,
			Failed:   1.0,
		},
	}

	settings := s.newSettings()
	nextConsumer := &consumertest.TracesSink{}
	proc, err := newTracesProcessor(context.Background(), settings, cfg, nextConsumer)
	require.NoError(t, err)

	err = proc.Start(context.Background(), componenttest.NewNopHost())
	require.NoError(t, err)

	traces := generateTracesWithIntent("failed")
	err = proc.ConsumeTraces(context.Background(), traces)
	require.NoError(t, err)

	var md metricdata.ResourceMetrics
	require.NoError(t, s.reader.Collect(context.Background(), &md))

	// Basic example metric verification
	m := metricdata.Metrics{
		Name:        "otelcol_processor_span_intent_spans_sampled",
		Description: "Number of spans sampled by intent type",
		Unit:        "{spans}",
		Data: metricdata.Sum[int64]{
			IsMonotonic: true,
			Temporality: metricdata.CumulativeTemporality,
			DataPoints: []metricdata.DataPoint[int64]{
				{
					Attributes: attribute.NewSet(
						attribute.String("intent", "failed"),
						attribute.String("sampled", "true"),
					),
					Value: 1,
				},
			},
		},
	}

	got := s.getMetric(m.Name, md)
	metricdatatest.AssertEqual(t, m, got, metricdatatest.IgnoreTimestamp())
}

