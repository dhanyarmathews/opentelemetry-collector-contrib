package spanintentprocessor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/spanintentprocessor/cache"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/spanintentprocessor/internal/utility"
)
// "hash/fnv"
const defaultHashSalt = "default-hash-seed"

type spanIntentProcessor struct {
	logger       *zap.Logger
	cfg          *Config
	nextConsumer consumer.Traces

	mu              sync.Mutex
	tdigestMutex    sync.Mutex
	traceDataBuffer map[pcommon.TraceID]*traceData
	tdigestMap      map[string]*utility.TDigest
	sampledTraces   cache.Cache[bool]
	unsampledTraces cache.Cache[bool]
	stopCh          chan struct{}

	// Metrics instruments
	mSpansReceived           metric.Int64Counter
	mNewTraceIDReceived      metric.Int64Counter
	mTraceBufferSize         metric.Int64UpDownCounter
	mSampledCacheHits        metric.Int64Counter
	mSampledCacheMisses      metric.Int64Counter
	mUnsampledCacheHits      metric.Int64Counter
	mUnsampledCacheMisses    metric.Int64Counter
	mTracesClassifiedTotal   metric.Int64Counter
	mTracesProcessed         metric.Int64Counter
	mTracesSampled           metric.Int64Counter
	mTracesUnsampled         metric.Int64Counter
	mErrorsTotal             metric.Int64Counter
	mProcessingDuration      metric.Int64Histogram
	mSamplingDecisionLatency metric.Int64Histogram
}

type traceData struct {
	resourceAttrs pcommon.Map
	spans         []ptrace.Span
}

func newSpanIntentProcessor(
	logger *zap.Logger,
	cfg *Config,
	nextConsumer consumer.Traces,
	meter metric.Meter,
) (*spanIntentProcessor, error) {
	// Use processor ID from config for context/logging/metrics
	processorID := cfg.ID.String()
	logger.Info("Starting spanintentprocessor", zap.String("id", processorID))

	// Create metric instruments directly from the meter
	mSpansReceived, err := meter.Int64Counter("processor.spanintent.spans_received")
	if err != nil {
		return nil, err
	}
	mNewTraceIDReceived, err := meter.Int64Counter("processor.spanintent.new_trace_id_received")
	if err != nil {
		return nil, err
	}
	mTraceBufferSize, err := meter.Int64UpDownCounter("processor.spanintent.trace_buffer_size")
	if err != nil {
		return nil, err
	}
	mSampledCacheHits, err := meter.Int64Counter("processor.spanintent.sampled_cache_hits")
	if err != nil {
		return nil, err
	}
	mSampledCacheMisses, err := meter.Int64Counter("processor.spanintent.sampled_cache_misses")
	if err != nil {
		return nil, err
	}
	mUnsampledCacheHits, err := meter.Int64Counter("processor.spanintent.unsampled_cache_hits")
	if err != nil {
		return nil, err
	}
	mUnsampledCacheMisses, err := meter.Int64Counter("processor.spanintent.unsampled_cache_misses")
	if err != nil {
		return nil, err
	}
	mTracesClassifiedTotal, err := meter.Int64Counter("processor.spanintent.traces_classified_total")
	if err != nil {
		return nil, err
	}
	mTracesProcessed, err := meter.Int64Counter("processor.spanintent.traces_processed")
	if err != nil {
		return nil, err
	}
	mTracesSampled, err := meter.Int64Counter("processor.spanintent.traces_sampled")
	if err != nil {
		return nil, err
	}
	mTracesUnsampled, err := meter.Int64Counter("processor.spanintent.traces_unsampled")
	if err != nil {
		return nil, err
	}
	mErrorsTotal, err := meter.Int64Counter("processor.spanintent.errors_total")
	if err != nil {
		return nil, err
	}
	mProcessingDuration, err := meter.Int64Histogram("processor.spanintent.processing_duration_ms")
	if err != nil {
		return nil, err
	}
	mSamplingDecisionLatency, err := meter.Int64Histogram("processor.spanintent.sampling_decision_latency_us")
	if err != nil {
		return nil, err
	}

	sampledCache, err := cache.NewCache[bool](cfg.SampledTracesCacheSize)
	if err != nil {
		return nil, err
	}
	unsampledCache, err := cache.NewCache[bool](cfg.UnsampledTracesCacheSize)
	if err != nil {
		return nil, err
	}

	return &spanIntentProcessor{
		logger:          logger,
		cfg:             cfg,
		nextConsumer:    nextConsumer,
		traceDataBuffer: make(map[pcommon.TraceID]*traceData),
		tdigestMap:      make(map[string]*utility.TDigest),
		sampledTraces:   sampledCache,
		unsampledTraces: unsampledCache,
		stopCh:          make(chan struct{}),

		mSpansReceived:           mSpansReceived,
		mNewTraceIDReceived:      mNewTraceIDReceived,
		mTraceBufferSize:         mTraceBufferSize,
		mSampledCacheHits:        mSampledCacheHits,
		mSampledCacheMisses:      mSampledCacheMisses,
		mUnsampledCacheHits:      mUnsampledCacheHits,
		mUnsampledCacheMisses:    mUnsampledCacheMisses,
		mTracesClassifiedTotal:   mTracesClassifiedTotal,
		mTracesProcessed:         mTracesProcessed,
		mTracesSampled:           mTracesSampled,
		mTracesUnsampled:         mTracesUnsampled,
		mErrorsTotal:             mErrorsTotal,
		mProcessingDuration:      mProcessingDuration,
		mSamplingDecisionLatency: mSamplingDecisionLatency,
	}, nil
}

func (p *spanIntentProcessor) Start(ctx context.Context, host component.Host) error {
	// go p.runTickLoop()
	p.logger.Info("spanintentprocessor started")
	return nil
}

func (p *spanIntentProcessor) Shutdown(ctx context.Context) error {
	close(p.stopCh)
	return nil
}

func (p *spanIntentProcessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	resourceSpans := td.ResourceSpans()

	p.logger.Info("Entering processTraces")

	// Initialize sets for normal, degraded, and failed traces
	normalSet := make(map[pcommon.TraceID]struct{})
	degradedSet := make(map[pcommon.TraceID]struct{})
	failedSet := make(map[pcommon.TraceID]struct{})

	tracesToProcess := make(map[pcommon.TraceID]*traceData) // To hold traces that are not in sampled or unsampled cache

	startTime := time.Now()

	// Loop through resource spans and process traces
	for i := 0; i < resourceSpans.Len(); i++ {
		rs := resourceSpans.At(i)
		resourceAttrs := rs.Resource().Attributes()

		ils := rs.ScopeSpans()
		for j := 0; j < ils.Len(); j++ {
			spans := ils.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				traceID := span.TraceID()

				p.mSpansReceived.Add(ctx, 1)

				// Lock and check if trace ID exists in sampled/unsampled caches
				p.mu.Lock()
				// If trace is not in the cache, initialize the trace entry
				if sampled, ok := p.sampledTraces.Get(traceID); ok && sampled {
					p.mSampledCacheHits.Add(context.Background(), 1)
					p.mu.Unlock()
					continue
				} else {
					p.mSampledCacheMisses.Add(context.Background(), 1)
				}

				if unsampled, ok := p.unsampledTraces.Get(traceID); ok && unsampled {
					p.mUnsampledCacheHits.Add(context.Background(), 1)
					p.mu.Unlock()
					continue
				} else {
					p.mUnsampledCacheMisses.Add(context.Background(), 1)
				}
				// data, exists := p.traceDataBuffer[traceID]
				data, exists := tracesToProcess[traceID]
				if !exists {
					// If trace doesn't exist, create a new entry
					p.mNewTraceIDReceived.Add(ctx, 1)
					attrCopy := pcommon.NewMap()
					resourceAttrs.CopyTo(attrCopy)
					data = &traceData{
						resourceAttrs: attrCopy,
						spans:         []ptrace.Span{},
					}
					// p.traceDataBuffer[traceID] = data
					tracesToProcess[traceID] = data
				}
				// Add the span to the trace data
				data.spans = append(data.spans, span)
				p.mu.Unlock()

				serviceName := "unknown"
				if attr, ok := data.resourceAttrs.Get("service.name"); ok && attr.Type() == pcommon.ValueTypeStr {
					serviceName = attr.Str()
				}
				opName := span.Name()
				key := fmt.Sprintf("%s_%s", serviceName, opName)

				p.tdigestMutex.Lock()
				// Check if there's already a TDigest for this serviceName + opName pair
				tdigest, exists := p.tdigestMap[key]
				if !exists {
					tdigest = utility.NewTDigest(100) // Create a new TDigest if it doesn't exist for this pair
					p.tdigestMap[key] = tdigest
				}

				// Add the latency of the current span to the TDigest for the service + operation pair
				latencyMs := float64(span.EndTimestamp()-span.StartTimestamp()) / 1e6
				tdigest.Add(latencyMs, 1)

				// Classify the latency
				q25 := tdigest.Quantile(0.25)
				q75 := tdigest.Quantile(0.75)
				q95 := tdigest.Quantile(0.95)
				switch {
				case latencyMs < q25:
					degradedSet[traceID] = struct{}{}
				case latencyMs >= q25 && latencyMs < q75:
					normalSet[traceID] = struct{}{}
				case latencyMs >= q75 && latencyMs < q95:
					degradedSet[traceID] = struct{}{}
				default:
					failedSet[traceID] = struct{}{}
				}

				p.tdigestMutex.Unlock()

			}
		}
	}

	// Call processTracesForSampling to decide which traces to sample
	p.processTracesForSampling(normalSet, degradedSet, failedSet, tracesToProcess)

	p.mSamplingDecisionLatency.Record(context.Background(), int64(time.Since(startTime)/time.Millisecond))
	return td, nil
}

func (p *spanIntentProcessor) processTracesForSampling(
	normalSet, degradedSet, failedSet map[pcommon.TraceID]struct{},
	tracesToProcess map[pcommon.TraceID]*traceData,
) {
	p.logger.Info("Entering processTracesForSampling")

	// Deduplicate traces (priority: failed > degraded > normal)
	for tid := range failedSet {
		delete(normalSet, tid)
		delete(degradedSet, tid)
	}
	for tid := range degradedSet {
		delete(normalSet, tid)
	}

	// Record classification metrics
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(normalSet)), metric.WithAttributes(attribute.String("classification_category", "normal")))
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(degradedSet)), metric.WithAttributes(attribute.String("classification_category", "degraded")))
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(failedSet)), metric.WithAttributes(attribute.String("classification_category", "failed")))

	// Convert sets to slices
	normalTraces := setToSlice(normalSet)
	degradedTraces := setToSlice(degradedSet)
	failedTraces := setToSlice(failedSet)

	traceGroups := map[string][]pcommon.TraceID{
		"normal":   normalTraces,
		"degraded": degradedTraces,
		"failed":   failedTraces,
	}

	biasMap := map[string]float64{
		"normal":   p.cfg.SamplingBias.Normal,
		"degraded": p.cfg.SamplingBias.Degraded,
		"failed":   p.cfg.SamplingBias.Failed,
	}

	totalTraces := len(normalTraces) + len(degradedTraces) + len(failedTraces)
	if totalTraces == 0 {
		return
	}

	// Calculate total budget
	totalBudget := int(float64(totalTraces) * p.cfg.SamplingPercentage)
	if totalBudget == 0 {
		totalBudget = 1 // Always sample at least one trace if any exist
	}

	// Step 1: Pre-allocate to bias==1 groups
	allocated := make(map[string]int)
	remainingBudget := totalBudget
	remainingBias := 0.0

	for label, traces := range traceGroups {
		if biasMap[label] == 1 {
			allocated[label] = len(traces) // sample all
			remainingBudget -= len(traces)
		} else {
			remainingBias += biasMap[label]
		}
	}

	// Step 2: Proportional allocation of remaining budget
	for label, traces := range traceGroups {
		if biasMap[label] < 1 {
			alloc := int((biasMap[label] / remainingBias) * float64(remainingBudget))
			if alloc > len(traces) {
				alloc = len(traces)
			}
			allocated[label] = alloc
		}
	}

	// Step 3: Sample top-N traces deterministically using traceID score
	for label, traces := range traceGroups {
		budget := allocated[label]
		if len(traces) == 0 {
			continue
		}

		// Score each trace using last 8 bytes of TraceID
		type scoredTrace struct {
			tid   pcommon.TraceID
			score float64
		}
		var scored []scoredTrace
		for _, tid := range traces {
			score := traceIDScore(tid)
			scored = append(scored, scoredTrace{tid: tid, score: score})
		}

		// Sort deterministically by score (lowest = highest priority)
		sort.Slice(scored, func(i, j int) bool {
			return scored[i].score < scored[j].score
		})

		// Sample up to budget
		for i, st := range scored {
			if i < budget {
				p.sampledTraces.Put(st.tid, true)
				p.mTracesSampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
				p.forwardTrace(st.tid, tracesToProcess[st.tid].spans, tracesToProcess[st.tid].resourceAttrs)
			} else {
				p.unsampledTraces.Put(st.tid, true)
				p.mTracesUnsampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
			}
		}
	}
}

// Converts a map[TraceID]struct{} to a slice of TraceIDs
func setToSlice(set map[pcommon.TraceID]struct{}) []pcommon.TraceID {
	slice := make([]pcommon.TraceID, 0, len(set))
	for tid := range set {
		slice = append(slice, tid)
	}
	return slice
}

// Deterministic score between 0 and 1 based on last 8 bytes of TraceID
func traceIDScore(tid pcommon.TraceID) float64 {
	low := binary.BigEndian.Uint64(tid[8:])
	return float64(low) / float64(^uint64(0)) // normalize to [0,1)
}

func extractSpanLatencies(td *traceData) []float64 {
	var latencies []float64
	for _, span := range td.spans {
		start := span.StartTimestamp().AsTime()
		end := span.EndTimestamp().AsTime()
		latency := end.Sub(start).Seconds() * 1000 // convert to milliseconds (float64)
		latencies = append(latencies, latency)
	}
	return latencies
}

func calculateVariance(data []float64) float64 {
	n := float64(len(data))
	if n == 0 {
		return 0
	}

	var sum, mean, variance float64

	for _, v := range data {
		sum += v
	}
	mean = sum / n

	for _, v := range data {
		diff := v - mean
		variance += diff * diff
	}

	return variance / n
}

func (p *spanIntentProcessor) getTraceGraphHash(data *traceData) (string, error) {
	var builder strings.Builder
	serviceName := "unknown"
	if attr, ok := data.resourceAttrs.Get("service.name"); ok && attr.Type() == pcommon.ValueTypeStr {
		serviceName = attr.Str()
	}

	spans := data.spans
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].StartTimestamp() < spans[j].StartTimestamp()
	})

	for _, span := range spans {
		builder.WriteString(serviceName)
		builder.WriteString(span.Name())
		builder.WriteString(strconv.FormatInt(int64(span.StartTimestamp()), 10))
		builder.WriteString(strconv.FormatInt(int64(span.EndTimestamp()), 10))

		// Add attributes keys and values for uniqueness if desired
		attrs := span.Attributes()
		keys := make([]string, 0, attrs.Len())
		attrs.Range(func(k string, v pcommon.Value) bool {
			keys = append(keys, k)
			return true
		})
		sort.Strings(keys)
		for _, k := range keys {
			builder.WriteString(k)
			val, _ := attrs.Get(k)
			builder.WriteString(val.AsString())
		}
	}

	hash := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(hash[:]), nil
}

func (p *spanIntentProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

func (p *spanIntentProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	p.logger.Info("spanintentprocessor received traces")
	_, err := p.processTraces(ctx, td)
	return err
}

func (p *spanIntentProcessor) forwardTrace(traceID pcommon.TraceID, spans []ptrace.Span, resourceAttrs pcommon.Map) {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	resourceAttrs.CopyTo(rs.Resource().Attributes())
	//rs.Resource().Attributes().InitFromMap(map[string]pcommon.Value{})
	// _ = rs.Resource().Attributes().FromRaw(map[string]interface{}{})

	ilss := rs.ScopeSpans().AppendEmpty()
	spansSlice := ilss.Spans()
	for _, span := range spans {
		//spanCopy := span.Clone()
		//spansSlice.Append(spanCopy)
		//spanCopy := spansSlice.AppendEmpty()
		//spanCopy.CopyFrom(span)
		span.CopyTo(spansSlice.AppendEmpty())
	}
	if err := p.nextConsumer.ConsumeTraces(context.Background(), td); err != nil {
		p.logger.Warn("failed to forward trace", zap.Error(err))
		//p.mErrorsTotal.Add(context.Background(), 1, attribute.String("error_type", "forwarding_failed"))
		p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "forwarding_failed")))
	}
}
