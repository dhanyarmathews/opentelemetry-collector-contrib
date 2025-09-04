package spanintentprocessor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

/*func (p *spanIntentProcessor) processTracesForSampling(normalSet map[pcommon.TraceID]struct{}, degradedSet map[pcommon.TraceID]struct{}, failedSet map[pcommon.TraceID]struct{}, tracesToProcess map[pcommon.TraceID]*traceData) {
	p.logger.Info("Entering processTracesForSampling")
	// Remove duplicates: traces in failed should not be in normal or degraded sets.
	for tid := range failedSet {
		delete(normalSet, tid)
		delete(degradedSet, tid)
	}
	for tid := range degradedSet {
		delete(normalSet, tid)
	}

	// Export metrics for normal, degraded, and failed traces
	p.logger.Info("Inside processTraces adding metrics")
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(normalSet)), metric.WithAttributes(attribute.String("classification_category", "normal")))
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(degradedSet)), metric.WithAttributes(attribute.String("classification_category", "degraded")))
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(failedSet)), metric.WithAttributes(attribute.String("classification_category", "failed")))

	type category int
        const (
                Normal category = iota
                Degraded
                Failed
        )

	// Now, we need to group traces by their trace graph hash.
	catTraceHashes := map[category]map[string]pcommon.TraceID{
		Normal:   {}, Degraded: {},Failed:   {},
	}
	for tid := range normalSet {
		data := tracesToProcess[tid]
		hash, err := p.getTraceGraphHash(data)
		if err != nil {
			p.logger.Warn("failed to get trace graph hash", zap.Error(err))
			p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "hash_generation_failed")))
			continue
		}
		catTraceHashes[Normal][hash] = tid
	}
	for tid := range degradedSet {
		data := tracesToProcess[tid]
		hash, err := p.getTraceGraphHash(data)
		if err != nil {
			p.logger.Warn("failed to get trace graph hash", zap.Error(err))
			p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "hash_generation_failed")))
			continue
		}
		catTraceHashes[Degraded][hash] = tid
	}
	for tid := range failedSet {
		data := tracesToProcess[tid]
		hash, err := p.getTraceGraphHash(data)
		if err != nil {
			p.logger.Warn("failed to get trace graph hash", zap.Error(err))
			p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "hash_generation_failed")))
			continue
		}
		catTraceHashes[Failed][hash] = tid
	}

	// Apply the final sampling based on the sampling bias and weight of each trace group
	for cat, traceHashToID := range catTraceHashes {
		var bias float64
		label := ""
		switch cat {
		case Normal:
			bias = p.cfg.SamplingBias.Normal
			label = "normal"
		case Degraded:
			bias = p.cfg.SamplingBias.Degraded
			label = "degraded"
		case Failed:
			bias = p.cfg.SamplingBias.Failed
			label = "failed"
		}

		finalSamplingRate := p.cfg.SamplingPercentage * bias
		for hash, tid := range traceHashToID {
			start := time.Now()
			hasher := fnv.New64a()
			_, _ = hasher.Write([]byte(defaultHashSalt))
			_, _ = hasher.Write([]byte(hash))
			hashedValue := hasher.Sum64()
			threshold := uint64(finalSamplingRate * float64(^uint64(0)))
			if hashedValue <= threshold {
				p.sampledTraces.Put(tid, true)
				p.mTracesSampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
				//p.forwardTrace(tid, traceSpansMap[tid].spans)
				p.forwardTrace(tid, tracesToProcess[tid].spans, tracesToProcess[tid].resourceAttrs)
			} else {
				p.unsampledTraces.Put(tid, true)
				p.mTracesUnsampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
			}
			p.mSamplingDecisionLatency.Record(context.Background(), time.Since(start).Microseconds())
		}
	}
}*/

func (p *spanIntentProcessor) processTracesForSampling(
	normalSet, degradedSet, failedSet map[pcommon.TraceID]struct{},
	tracesToProcess map[pcommon.TraceID]*traceData,
) {
	p.logger.Info("Entering processTracesForSampling")

	// Deduplicate traces among categories (failed > degraded > normal)
	for tid := range failedSet {
		delete(normalSet, tid)
		delete(degradedSet, tid)
	}
	for tid := range degradedSet {
		delete(normalSet, tid)
	}

	// Export classification counts metrics
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(normalSet)), metric.WithAttributes(attribute.String("classification_category", "normal")))
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(degradedSet)), metric.WithAttributes(attribute.String("classification_category", "degraded")))
	p.mTracesClassifiedTotal.Add(context.Background(), int64(len(failedSet)), metric.WithAttributes(attribute.String("classification_category", "failed")))

	type category int
	const (
		Normal category = iota
		Degraded
		Failed
	)

	// Group traces by DAG hash for each category
	catTraceHashes := map[category]map[string][]pcommon.TraceID{
		Normal:   {},
		Degraded: {},
		Failed:   {},
	}
	for tid := range normalSet {
		data := tracesToProcess[tid]
		hash, err := p.getTraceGraphHash(data)
		if err != nil {
			p.logger.Warn("failed to get trace graph hash", zap.Error(err))
			p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "hash_generation_failed")))
			continue
		}
		catTraceHashes[Normal][hash] = append(catTraceHashes[Normal][hash], tid)
	}
	for tid := range degradedSet {
		data := tracesToProcess[tid]
		hash, err := p.getTraceGraphHash(data)
		if err != nil {
			p.logger.Warn("failed to get trace graph hash", zap.Error(err))
			p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "hash_generation_failed")))
			continue
		}
		catTraceHashes[Degraded][hash] = append(catTraceHashes[Degraded][hash], tid)
	}
	for tid := range failedSet {
		data := tracesToProcess[tid]
		hash, err := p.getTraceGraphHash(data)
		if err != nil {
			p.logger.Warn("failed to get trace graph hash", zap.Error(err))
			p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "hash_generation_failed")))
			continue
		}
		catTraceHashes[Failed][hash] = append(catTraceHashes[Failed][hash], tid)
	}

	categoryLabel := func(cat category) string {
		switch cat {
		case Normal:
			return "normal"
		case Degraded:
			return "degraded"
		case Failed:
			return "failed"
		default:
			return "unknown"
		}
	}

	// Pre-store biases in a map for easy lookup
	biasMap := map[category]float64{
		Normal:   p.cfg.SamplingBias.Normal,
		Degraded: p.cfg.SamplingBias.Degraded,
		Failed:   p.cfg.SamplingBias.Failed,
	}

	// For each DAG hash found in any category, do the sampling
	// Collect all unique hashes from all categories
	hashSet := make(map[string]struct{})
	for cat := range catTraceHashes {
		for hash := range catTraceHashes[cat] {
			hashSet[hash] = struct{}{}
		}
	}

	for hash := range hashSet {
		// Collect trace slices per category, default to empty if none
		traceGroups := map[category][]pcommon.TraceID{
			Normal:   catTraceHashes[Normal][hash],
			Degraded: catTraceHashes[Degraded][hash],
			Failed:   catTraceHashes[Failed][hash],
		}

		// Calculate total number of traces across categories for this hash
		totalTraces := 0
		for _, traces := range traceGroups {
			totalTraces += len(traces)
		}
		if totalTraces == 0 {
			continue
		}

		// Calculate sum of biases only for categories present (with non-empty trace slices)
		var sumBias float64
		for cat, traces := range traceGroups {
			if len(traces) > 0 {
				sumBias += biasMap[cat]
			}
		}
		if sumBias == 0 {
			// Avoid division by zero, skip if no biases
			continue
		}

		// Total sampling budget for this hash (all categories combined)
		totalBudget := int(float64(totalTraces) * p.cfg.SamplingPercentage)
		if totalBudget == 0 {
			totalBudget = 1 // At least one sample if any traces exist
		}

		//start := time.Now()

		// For each category, allocate budget proportionally by bias share, select top-variance traces
		for cat, traces := range traceGroups {
			label := categoryLabel(cat)
			if len(traces) == 0 {
				continue
			}

			budget := int(float64(totalBudget) * (biasMap[cat] / sumBias))
			if budget > len(traces) {
				budget = len(traces)
			}

			type traceVariance struct {
				tid      pcommon.TraceID
				variance float64
			}
			var variances []traceVariance

			for _, tid := range traces {
				latencies := extractSpanLatencies(tracesToProcess[tid])
				variance := calculateVariance(latencies)
				variances = append(variances, traceVariance{tid: tid, variance: variance})
			}

			sort.Slice(variances, func(i, j int) bool {
				return variances[i].variance > variances[j].variance
			})

			for i, tv := range variances {
				if i < budget {
					p.sampledTraces.Put(tv.tid, true)
					p.mTracesSampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
					p.forwardTrace(tv.tid, tracesToProcess[tv.tid].spans, tracesToProcess[tv.tid].resourceAttrs)
				} else {
					p.unsampledTraces.Put(tv.tid, true)
					p.mTracesUnsampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
				}
			}
		}

		// p.mSamplingDecisionLatency.Record(context.Background(), time.Since(start).Microseconds())
	}
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
