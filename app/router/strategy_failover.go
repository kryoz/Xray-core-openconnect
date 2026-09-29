package router

import (
	"context"
	"slices"
	"sort"
	"strings"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
)

const defaultFailoverThreshold = 2

// FailoverStrategy keeps traffic on the highest-priority outbound (selector
// order) and switches to the next one only after the current one has failed
// `threshold` consecutive probes. A single successful probe resets the streak,
// so failback to the primary is automatic.
type FailoverStrategy struct {
	selectors []string
	threshold int

	ctx         context.Context
	observatory extension.Observatory
}

func NewFailoverStrategy(selectors []string, settings *StrategyFailoverConfig) *FailoverStrategy {
	threshold := defaultFailoverThreshold
	if settings != nil && settings.FailThreshold > 0 {
		threshold = int(settings.FailThreshold)
	}
	return &FailoverStrategy{
		selectors: selectors,
		threshold: threshold,
	}
}

func (s *FailoverStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	if err := core.OptionalFeatures(ctx, func(o extension.Observatory) error {
		s.observatory = o
		return nil
	}); err != nil {
		errors.LogWarning(ctx, "failover strategy: cannot acquire observatory feature: ", err)
	} else if s.observatory == nil {
		errors.LogWarning(ctx, "failover strategy: observatory is not available, failover is disabled (always using the first selector)")
	}
}

// GetPrincipleTarget implements BalancingPrincipleTarget.
func (s *FailoverStrategy) GetPrincipleTarget(candidates []string) []string {
	return orderCandidates(candidates, s.selectors)
}

// PickOutbound returns the first up candidate in selector order, or ""
// when all candidates are down. An empty tag routes to the balancing
// rule's fallbackTag; without one the dispatcher falls back to the
// default outbound handler, so configure fallbackTag for the all-down case.
func (s *FailoverStrategy) PickOutbound(candidates []string) string {
	status := s.currentStatus()
	for _, tag := range orderCandidates(candidates, s.selectors) {
		if isUp(tag, status, s.threshold) {
			return tag
		}
	}
	return ""
}

// currentStatus returns the observatory status by tag, or nil when the
// observatory is unavailable or returned no report.
func (s *FailoverStrategy) currentStatus() map[string]*observatory.OutboundStatus {
	if s.observatory == nil {
		return nil
	}
	report, err := s.observatory.GetObservation(s.ctx)
	if err != nil {
		return nil
	}
	result, ok := report.(*observatory.ObservationResult)
	if !ok {
		return nil
	}
	m := make(map[string]*observatory.OutboundStatus, len(result.Status))
	for _, v := range result.Status {
		m[v.OutboundTag] = v
	}
	return m
}

// isUp reports whether the outbound is up. A tag without observation data
// (observatory off, tag not in subjectSelector) is considered up.
func isUp(tag string, status map[string]*observatory.OutboundStatus, threshold int) bool {
	v, found := status[tag]
	return !found || v.FailStreak < int64(threshold)
}

// orderCandidates orders tags by the position of the first matching
// selector; ties keep alphabetical order.
func orderCandidates(tags []string, selectors []string) []string {
	rank := make(map[string]int, len(tags))
	for _, tag := range tags {
		r := len(selectors)
		for i, sel := range selectors {
			if strings.HasPrefix(tag, sel) {
				r = i
				break
			}
		}
		rank[tag] = r
	}
	ordered := slices.Clone(tags)
	sort.SliceStable(ordered, func(i, j int) bool {
		if rank[ordered[i]] != rank[ordered[j]] {
			return rank[ordered[i]] < rank[ordered[j]]
		}
		return ordered[i] < ordered[j]
	})
	return ordered
}
