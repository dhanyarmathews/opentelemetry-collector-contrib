package spanintentprocessor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"
	"hash/fnv"
	"math/rand"
	"math"
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
	//decayingTDigestMap map[string]*decayingTDigest
	modelTDigestMap map[string]*decayingTDigest
	quantileEMAMap   map[string]*quantileEMA           // smoothed q75/q95
	emaAlpha         float64
	seenTraceIDs map[pcommon.TraceID]struct{}
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

type decayingTDigest struct {
    td          *utility.TDigest
    weightSum   float64
    decayFactor float64
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
		modelTDigestMap: make(map[string]*decayingTDigest),
		quantileEMAMap:  make(map[string]*quantileEMA),
		emaAlpha:        0.1, // smoothing factor: adjust as needed
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

type quantileEMA struct {
    Q75 float64
    Q95 float64
    Initialized bool
}

func (d *decayingTDigest) Add(latency float64) {
    // Apply decay to existing weights
    d.weightSum *= d.decayFactor
    // Add new latency with weight 1
    d.td.Add(latency, 1)
    d.weightSum += 1
}

func (d *decayingTDigest) Quantile(q float64) float64 {
    if d.weightSum < 1e-6 {
        return 0 // no data yet, fallback to zero or some default
    }
    return d.td.Quantile(q)
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

func (p *spanIntentProcessor) init() {
	p.seenTraceIDs = make(map[pcommon.TraceID]struct{})
	rand.Seed(time.Now().UnixNano())
}

func (p *spanIntentProcessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
    resourceSpans := td.ResourceSpans()
    p.logger.Info("Entering processTraces")

    // Init sets
    normalSet := make(map[pcommon.TraceID]struct{})
    degradedSet := make(map[pcommon.TraceID]struct{})
    failedSet := make(map[pcommon.TraceID]struct{})

    tracesToProcess := make(map[pcommon.TraceID]*traceData)
    tracesToForwardImmediately := make(map[pcommon.TraceID]*traceData)

    startTime := time.Now()

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
                if sampled, ok := p.sampledTraces.Get(traceID); ok && sampled {
                    p.mSampledCacheHits.Add(ctx, 1)
                    traceDataItem := getOrCreateTrace(traceID, resourceAttrs, tracesToForwardImmediately)
                    traceDataItem.spans = append(traceDataItem.spans, span)
                    p.mu.Unlock()
                    continue
                }
                if unsampled, ok := p.unsampledTraces.Get(traceID); ok && unsampled {
                    p.mUnsampledCacheHits.Add(ctx, 1)
                    p.mu.Unlock()
                    continue
                }

                traceDataItem := getOrCreateTrace(traceID, resourceAttrs, tracesToProcess)
                traceDataItem.spans = append(traceDataItem.spans, span)
                p.mu.Unlock()

                serviceName := "unknown"
                if attr, ok := traceDataItem.resourceAttrs.Get("service.name"); ok && attr.Type() == pcommon.ValueTypeStr {
                    serviceName = attr.Str()
                }

                key := fmt.Sprintf("%s_%s", serviceName, span.Name())
                latencyMs := float64(span.EndTimestamp() - span.StartTimestamp()) / 1e6

                p.tdigestMutex.Lock()

		td, ok := p.tdigestMap[key]
		if !ok {
			td = utility.NewTDigest(100)
			p.tdigestMap[key] = td
		}
		td.Add(latencyMs, 1)
		//if td.TotalWeight() >= 20 {
		q75 := td.Quantile(0.75)
		q95 := td.Quantile(0.95)
		ema, exists := p.quantileEMAMap[key]
		if !exists {
			p.quantileEMAMap[key] = &quantileEMA{
				Q75: q75,
				Q95: q95,
				Initialized: true,
			}
		} else {
			alpha := p.emaAlpha
			ema.Q75 = alpha*q75 + (1-alpha)*ema.Q75
			ema.Q95 = alpha*q95 + (1-alpha)*ema.Q95
		}

                p.tdigestMutex.Unlock()

                if attr, ok := span.Attributes().Get("http.status_code"); ok {
                    if attr.Type() == pcommon.ValueTypeInt && attr.Int() != 200 {
                        failedSet[traceID] = struct{}{}
                        continue
                    }
                }

		if ema, ok := p.quantileEMAMap[key]; ok && ema.Initialized {
			switch {
				case latencyMs < ema.Q75:
					normalSet[traceID] = struct{}{}
				case latencyMs < ema.Q95:
					degradedSet[traceID] = struct{}{}
				default:
					failedSet[traceID] = struct{}{}
				}
			} else {
				normalSet[traceID] = struct{}{}
			}

                /*switch {
                case latencyMs < q75:
                    normalSet[traceID] = struct{}{}
                case latencyMs >= q75 && latencyMs < q95:
                    degradedSet[traceID] = struct{}{}
                default:
                    failedSet[traceID] = struct{}{}
                }*/
            }
        }
    }

    p.processTracesForSampling(normalSet, degradedSet, failedSet, tracesToProcess)

    for tid, data := range tracesToForwardImmediately {
        p.forwardTrace(tid, data.spans, data.resourceAttrs)
    }

    p.mSamplingDecisionLatency.Record(ctx, int64(time.Since(startTime)/time.Millisecond))
    return td, nil
}

func (p *spanIntentProcessor) processTracesForSampling(
    normalSet, degradedSet, failedSet map[pcommon.TraceID]struct{},
    tracesToProcess map[pcommon.TraceID]*traceData,
) {
    p.logger.Info("Entering processTracesForSampling")

    // Priority: failed > degraded > normal
    for tid := range failedSet {
        delete(normalSet, tid)
        delete(degradedSet, tid)
    }
    for tid := range degradedSet {
        delete(normalSet, tid)
    }

    p.mTracesClassifiedTotal.Add(context.Background(), int64(len(normalSet)), metric.WithAttributes(attribute.String("classification_category", "normal")))
    p.mTracesClassifiedTotal.Add(context.Background(), int64(len(degradedSet)), metric.WithAttributes(attribute.String("classification_category", "degraded")))
    p.mTracesClassifiedTotal.Add(context.Background(), int64(len(failedSet)), metric.WithAttributes(attribute.String("classification_category", "failed")))

    traceGroups := map[string][]pcommon.TraceID{
        "normal":   setToSlice(normalSet),
        "degraded": setToSlice(degradedSet),
        "failed":   setToSlice(failedSet),
    }

    biasMap := map[string]float64{
        "normal":   p.cfg.SamplingBias.Normal,
        "degraded": p.cfg.SamplingBias.Degraded,
        "failed":   p.cfg.SamplingBias.Failed,
    }

    totalTraces := len(traceGroups["normal"]) + len(traceGroups["degraded"]) + len(traceGroups["failed"])
    if totalTraces == 0 {
        return
    }

    totalBudget := int(float64(totalTraces) * p.cfg.SamplingPercentage)
    if totalBudget == 0 {
        totalBudget = 1
    }

    allocated := make(map[string]int)
    remainingBudget := totalBudget
    remainingBias := 0.0

    for label, traces := range traceGroups {
        if biasMap[label] == 1 {
            allocated[label] = len(traces)
            remainingBudget -= len(traces)
        } else {
            remainingBias += biasMap[label]
        }
    }

    for label, traces := range traceGroups {
        if biasMap[label] < 1 {
            alloc := int((biasMap[label] / remainingBias) * float64(remainingBudget))
            if alloc > len(traces) {
                alloc = len(traces)
            }
            allocated[label] = alloc
        }
    }

    for label, traceIDs := range traceGroups {
        budget := allocated[label]
        if budget == 0 || len(traceIDs) == 0 {
            continue
        }

        // Build weighted trace list
        weighted := make([]weightedTrace, 0, len(traceIDs))
        maxLatency := 1.0

        // First pass: compute max latency
        for _, tid := range traceIDs {
            trace := tracesToProcess[tid]
            highestLatency := 0.0
            for _, span := range trace.spans {
                latency := float64(span.EndTimestamp() - span.StartTimestamp()) / 1e6
                if latency > highestLatency {
                    highestLatency = latency
                }
            }
            if highestLatency > maxLatency {
                maxLatency = highestLatency
            }
        }

        // Second pass: assign normalized weights
        for _, tid := range traceIDs {
            trace := tracesToProcess[tid]
            highestLatency := 0.0
            for _, span := range trace.spans {
                latency := float64(span.EndTimestamp() - span.StartTimestamp()) / 1e6
                if latency > highestLatency {
                    highestLatency = latency
                }
            }
            normWeight := highestLatency / maxLatency
            if normWeight == 0 {
                normWeight = 0.01 // Avoid 0 weights
            }
            weighted = append(weighted, weightedTrace{tid: tid, weight: normWeight})
        }

        selected := weightedReservoirSample(weighted, budget)

        // Mark and forward selected traces
        for _, tid := range traceIDs {
            if _, ok := selected[tid]; ok {
                p.sampledTraces.Put(tid, true)
                p.mTracesSampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
                p.forwardTrace(tid, tracesToProcess[tid].spans, tracesToProcess[tid].resourceAttrs)
            } else {
                p.unsampledTraces.Put(tid, true)
                p.mTracesUnsampled.Add(context.Background(), 1, metric.WithAttributes(attribute.String("sampling_category", label)))
            }
        }
    }
}

type weightedTrace struct {
    tid    pcommon.TraceID
    weight float64
}

func weightedReservoirSample(traces []weightedTrace, k int) map[pcommon.TraceID]struct{} {
    selected := make([]struct {
        tid   pcommon.TraceID
        score float64
    }, 0, k)

    for _, wt := range traces {
        u := rand.Float64()
        score := math.Pow(u, 1.0/wt.weight) // higher weight → higher score

        if len(selected) < k {
            selected = append(selected, struct {
                tid   pcommon.TraceID
                score float64
            }{wt.tid, score})
        } else {
            // Find the trace with the lowest score
            minIdx := 0
            for i := 1; i < k; i++ {
                if selected[i].score < selected[minIdx].score {
                    minIdx = i
                }
            }

            if score > selected[minIdx].score {
                selected[minIdx] = struct {
                    tid   pcommon.TraceID
                    score float64
                }{wt.tid, score}
            }
        }
    }

    result := make(map[pcommon.TraceID]struct{}, k)
    for _, st := range selected {
        result[st.tid] = struct{}{}
    }
    return result
}

// getOrCreateTrace returns an existing traceData object from the map or creates a new one
func getOrCreateTrace(
    traceID pcommon.TraceID,
    resourceAttrs pcommon.Map,
    traceMap map[pcommon.TraceID]*traceData,
) *traceData {
    if data, exists := traceMap[traceID]; exists {
        return data
    }

    attrCopy := pcommon.NewMap()
    resourceAttrs.CopyTo(attrCopy)

    traceDataItem := &traceData{
        resourceAttrs: attrCopy,
        spans:         []ptrace.Span{},
    }

    traceMap[traceID] = traceDataItem
    return traceDataItem
}

func hashTraceID(tid pcommon.TraceID) uint64 {
    h := fnv.New64a()
    h.Write(tid[:])
    return h.Sum64()
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
