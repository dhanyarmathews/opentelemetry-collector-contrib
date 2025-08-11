package spanintentprocessor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
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

const defaultHashSalt = "default-hash-seed"

type spanIntentProcessor struct {
	logger       *zap.Logger
	cfg          *Config
	nextConsumer consumer.Traces

	mu              sync.Mutex
	traceDataBuffer map[pcommon.TraceID]*traceData
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
	go p.runTickLoop()
	return nil
}

func (p *spanIntentProcessor) Shutdown(ctx context.Context) error {
	close(p.stopCh)
	return nil
}

func (p *spanIntentProcessor) runTickLoop() {
	ticker := time.NewTicker(p.cfg.TickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.processBufferedSpans()
		case <-p.stopCh:
			return
		}
	}
}

func (p *spanIntentProcessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	resourceSpans := td.ResourceSpans()
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

				p.mu.Lock()
				data, exists := p.traceDataBuffer[traceID]
				if !exists {
					p.mNewTraceIDReceived.Add(ctx, 1)
					attrCopy := pcommon.NewMap()
					resourceAttrs.CopyTo(attrCopy)
					data = &traceData{
						resourceAttrs: attrCopy,
						spans:         []ptrace.Span{},
					}
					p.traceDataBuffer[traceID] = data
				}
				data.spans = append(data.spans, span)
				p.mu.Unlock()
			}
		}
	}
	return td, nil
}

func (p *spanIntentProcessor) processBufferedSpans() {
	start := time.Now()
	defer func() {
		p.mProcessingDuration.Record(context.Background(), time.Since(start).Milliseconds())
	}()

	p.mu.Lock()
	traceDataCopy := p.traceDataBuffer
	p.traceDataBuffer = make(map[pcommon.TraceID]*traceData)
	p.mTraceBufferSize.Add(context.Background(), int64(len(traceDataCopy)))
	p.mu.Unlock()

	if len(traceDataCopy) == 0 {
		return
	}

	traceSpansMap := make(map[pcommon.TraceID]*traceData)
	for traceID, data := range traceDataCopy {
		if sampled, ok := p.sampledTraces.Get(traceID); ok && sampled {
			p.mSampledCacheHits.Add(context.Background(), 1)
			continue
		} else {
			p.mSampledCacheMisses.Add(context.Background(), 1)
		}
		if unsampled, ok := p.unsampledTraces.Get(traceID); ok && unsampled {
			p.mUnsampledCacheHits.Add(context.Background(), 1)
			continue
		} else {
			p.mUnsampledCacheMisses.Add(context.Background(), 1)
		}
		traceSpansMap[traceID] = data
	}
	if len(traceSpansMap) == 0 {
		return
	}

	tdigestMap := make(map[string]*utility.TDigest)
	for _, data := range traceSpansMap {
		serviceName := "unknown"
		if attr, ok := data.resourceAttrs.Get("service.name"); ok && attr.Type() == pcommon.ValueTypeStr {
			serviceName = attr.Str()
		}
		for _, span := range data.spans {
			opName := span.Name()
			key := fmt.Sprintf("%s_%s", serviceName, opName)
			td, ok := tdigestMap[key]
			if !ok {
				td = utility.NewTDigest(100)
				tdigestMap[key] = td
			}
			latencyMs := float64(span.EndTimestamp()-span.StartTimestamp()) / 1e6
			td.Add(latencyMs, 1)
		}
	}

	type category int
	const (
		Normal category = iota
		Degraded
		Failed
	)

	classifyLatency := func(td *utility.TDigest, latency float64) category {
		p25 := td.Quantile(0.25)
		p90 := td.Quantile(0.90)
		p95 := td.Quantile(0.95)
		switch {
		case latency > p95:
			return Failed
		case latency >= p90 || latency < p25:
			return Degraded
		default:
			return Normal
		}
	}

	normalSet := make(map[pcommon.TraceID]struct{})
	degradedSet := make(map[pcommon.TraceID]struct{})
	failedSet := make(map[pcommon.TraceID]struct{})

	for traceID, data := range traceSpansMap {
		serviceName := "unknown"
		if attr, ok := data.resourceAttrs.Get("service.name"); ok && attr.Type() == pcommon.ValueTypeStr {
			serviceName = attr.Str()
		}

		traceCategories := make(map[category]struct{})
		for _, span := range data.spans {
			key := fmt.Sprintf("%s_%s", serviceName, span.Name())
			td := tdigestMap[key]
			cat := classifyLatency(td, float64(span.EndTimestamp()-span.StartTimestamp())/1e6)
			traceCategories[cat] = struct{}{}
		}

		if _, ok := traceCategories[Failed]; ok {
			failedSet[traceID] = struct{}{}
		} else if _, ok := traceCategories[Degraded]; ok {
			degradedSet[traceID] = struct{}{}
		} else {
			normalSet[traceID] = struct{}{}
		}
	}

	// Remove overlaps: failed > degraded > normal
	for tid := range failedSet {
		delete(degradedSet, tid)
		delete(normalSet, tid)
	}
	for tid := range degradedSet {
		delete(normalSet, tid)
	}

	for range normalSet {
		p.mTracesClassifiedTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("classification_category", "normal")))
	}
	for range degradedSet {
		p.mTracesClassifiedTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("classification_category", "degraded")))
	}
	for range failedSet {
		p.mTracesClassifiedTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("classification_category", "failed")))
	}
	p.mTracesProcessed.Add(context.Background(), int64(len(normalSet)+len(degradedSet)+len(failedSet)))

	catTraceHashes := map[category]map[string]pcommon.TraceID{
		Normal:   {},
		Degraded: {},
		Failed:   {},
	}

	for cat, traceIDs := range map[category]map[pcommon.TraceID]struct{}{
		Normal:   normalSet,
		Degraded: degradedSet,
		Failed:   failedSet,
	} {
		for tid := range traceIDs {
			data := traceSpansMap[tid]
			hash, err := p.getTraceGraphHash(data)
			if err != nil {
				p.logger.Warn("failed to get trace graph hash", zap.Error(err))
				p.mErrorsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("error_type", "hash_generation_failed")))
				continue
			}
			catTraceHashes[cat][hash] = tid
		}
	}

	for cat, traceHashToID := range catTraceHashes {
		bias := 1.0
		label := "normal"
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
				p.forwardTrace(tid, traceSpansMap[tid].spans)
			} else {
				p.unsampledTraces.Put(tid, true)
				p.mTracesUnsampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
			}

			p.mSamplingDecisionLatency.Record(context.Background(), time.Since(start).Microseconds())
		}
	}
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
	_, err := p.processTraces(ctx, td)
	return err
}

func (p *spanIntentProcessor) forwardTrace(traceID pcommon.TraceID, spans []ptrace.Span) {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	//rs.Resource().Attributes().InitFromMap(map[string]pcommon.Value{})
	_ = rs.Resource().Attributes().FromRaw(map[string]interface{}{})


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
