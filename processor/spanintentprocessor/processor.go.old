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
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/spanintentprocessor/cache"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/spanintentprocessor/internal/utility"
)

const defaultHashSalt = "default-hash-seed"

type spanIntentProcessor struct {
	logger *zap.Logger
	cfg    *Config

	mu sync.Mutex
	// Buffer spans grouped by trace ID AND their resource attributes
	traceDataBuffer map[pcommon.TraceID]*traceData

	sampledTraces   cache.Cache[bool]
	unsampledTraces cache.Cache[bool]

	nextConsumer consumer.Traces
	stopCh       chan struct{}
}

// traceData stores spans and resource attributes for a trace
type traceData struct {
	resourceAttrs pcommon.Map
	spans        []ptrace.Span
}

type Option func(*spanIntentProcessor)

func newSpanIntentProcessor(logger *zap.Logger, cfg *Config, nextConsumer consumer.Traces) (*spanIntentProcessor, error) {
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

// processTraces buffers all spans grouped by traceID along with resource attributes
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

				p.mu.Lock()
				data, exists := p.traceDataBuffer[traceID]
				if !exists {
					// Copy resource attributes map to avoid mutation issues
					attrCopy := pcommon.NewMap()
					resourceAttrs.CopyTo(attrCopy)
					data = &traceData{
						resourceAttrs: attrCopy,
						spans:        []ptrace.Span{},
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

// processBufferedSpans processes buffered spans grouped by traceID and resourceAttrs
func (p *spanIntentProcessor) processBufferedSpans() {
	p.mu.Lock()
	traceDataCopy := p.traceDataBuffer
	p.traceDataBuffer = make(map[pcommon.TraceID]*traceData)
	p.mu.Unlock()

	if len(traceDataCopy) == 0 {
		return
	}

	// Filter out traces with known sampling decisions
	traceSpansMap := make(map[pcommon.TraceID]*traceData)
	for traceID, data := range traceDataCopy {
		if sampled, ok := p.sampledTraces.Get(traceID); ok && sampled {
			continue
		}
		if unsampled, ok := p.unsampledTraces.Get(traceID); ok && unsampled {
			continue
		}
		traceSpansMap[traceID] = data
	}
	if len(traceSpansMap) == 0 {
		return
	}

	// Step 2 and 3: group spans by serviceName+operation, build TDigest per group
	tdigestMap := make(map[string]*utility.TDigest) // key: service_op
	for _, data := range traceSpansMap {
		serviceName := "unknown"
		if serviceNameAttr, ok := data.resourceAttrs.Get("service.name"); ok && serviceNameAttr.Type() == pcommon.ValueTypeStr {
			serviceName = serviceNameAttr.Str()
		}
		//serviceNameAttr, ok := data.resourceAttrs.Get("service.name")
		//serviceName := "unknown"
		//if serviceNameAttr.Type() == pcommon.ValueTypeStr {
		//	serviceName = serviceNameAttr.StringVal()
		//}

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

	// classifyLatency based on percentiles
	classifyLatency := func(td *utility.TDigest, latency float64) category {
		p25 := td.Quantile(0.25)
		p90 := td.Quantile(0.90)
		p95 := td.Quantile(0.95)

		switch {
		case latency > p95:
			return Failed
		case latency >= p90 && latency <= p95:
			return Degraded
		case latency < p25:
			return Normal
		default:
			return Normal
		}
	}

	// Step 4: classify each traceID into categories based on its spans
	normalSet := make(map[pcommon.TraceID]struct{})
	degradedSet := make(map[pcommon.TraceID]struct{})
	failedSet := make(map[pcommon.TraceID]struct{})

	for traceID, data := range traceSpansMap {
		serviceName := "unknown"
                if serviceNameAttr, ok := data.resourceAttrs.Get("service.name"); ok && serviceNameAttr.Type() == pcommon.ValueTypeStr {
                        serviceName = serviceNameAttr.Str()
                }
		
		//serviceNameAttr := data.resourceAttrs.Get("service.name")
		//serviceName := "unknown"
		//if serviceNameAttr.Type() == pcommon.ValueTypeString {
		//	serviceName = serviceNameAttr.StringVal()
		//}

		traceCategories := make(map[category]struct{})
		for _, span := range data.spans {
			opName := span.Name()
			key := fmt.Sprintf("%s_%s", serviceName, opName)
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

	// Step 5: remove overlaps between categories
	for tid := range failedSet {
		delete(degradedSet, tid)
		delete(normalSet, tid)
	}
	for tid := range degradedSet {
		delete(normalSet, tid)
	}

	// Step 6: group traceIDs by trace graph hash per category
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
				continue
			}
			catTraceHashes[cat][hash] = tid
		}
	}

	// Step 7: sample traces based on sampling bias & percentage
	for cat, traceHashToID := range catTraceHashes {
		bias := 1.0
		switch cat {
		case Normal:
			bias = p.cfg.SamplingBias.Normal
		case Degraded:
			bias = p.cfg.SamplingBias.Degraded
		case Failed:
			bias = p.cfg.SamplingBias.Failed
		}
		finalSamplingRate := p.cfg.SamplingPercentage * bias

		for hash, tid := range traceHashToID {
			hasher := fnv.New64a()
			_, _ = hasher.Write([]byte(defaultHashSalt))
			_, _ = hasher.Write([]byte(hash))
			hashedValue := hasher.Sum64()

			threshold := uint64(finalSamplingRate * float64(^uint64(0)))

			if hashedValue <= threshold {
				p.sampledTraces.Put(tid, true)
				p.forwardTrace(tid, traceSpansMap[tid].spans)
			} else {
				p.unsampledTraces.Put(tid, true)
			}
		}
	}
}

// getTraceGraphHash returns a SHA256 hash based on span resource serviceName, span name, start/end timestamps to represent the trace trajectory
func (p *spanIntentProcessor) getTraceGraphHash(data *traceData) (string, error) {
	var builder strings.Builder

	serviceName := "unknown"
	if serviceNameAttr, ok := data.resourceAttrs.Get("service.name"); ok && serviceNameAttr.Type() == pcommon.ValueTypeStr {
		serviceName = serviceNameAttr.Str()
	}
	//serviceNameAttr := data.resourceAttrs.Get("service.name")
	//serviceName := "unknown"
	//if serviceNameAttr.Type() == pcommon.ValueTypeString {
	//	serviceName = serviceNameAttr.StringVal()
	//}

	// Sort spans by start time for consistent hash
	spans := data.spans
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].StartTimestamp() < spans[j].StartTimestamp()
	})
	for _, span := range spans {
		builder.WriteString(serviceName)
		builder.WriteString(span.Name())
		builder.WriteString(strconv.FormatInt(int64(span.StartTimestamp()), 10))
		builder.WriteString(strconv.FormatInt(int64(span.EndTimestamp()), 10))
		// Add parent span ID or other edges info if needed here
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

	// Copy the resource attributes from the first span's resource (optional enhancement)
	// But here, just copying spans under default ResourceSpans with empty resource:
	scopeSpans := rs.ScopeSpans().AppendEmpty()
	spanSlice := scopeSpans.Spans()

	for _, span := range spans {
		copiedSpan := spanSlice.AppendEmpty()
		span.CopyTo(copiedSpan)
	}

	err := p.nextConsumer.ConsumeTraces(context.Background(), td)
	if err != nil {
		p.logger.Error("Failed to forward trace", zap.String("traceID", traceID.String()), zap.Error(err))
	} else {
		p.logger.Info("Forwarded trace downstream", zap.String("traceID", traceID.String()), zap.Int("spanCount", len(spans)))
	}
}

