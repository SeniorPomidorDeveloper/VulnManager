package dedup

import (
	"errors"
	"fmt"
)

type (
	ScorerID string
	Points   int
	Verdict  string
)

const (
	VerdictMerge    Verdict = "merge"
	VerdictReview   Verdict = "review"
	VerdictSeparate Verdict = "separate"
)

const (
	FeatureKind FeatureID = "kind"

	weightedID      ScorerID = "weighted"
	weightedVersion Version  = 3

	maxPoints Points = 1000
)

var ErrInvalidScorer = errors.New("dedup: invalid scorer")

type MatchReason struct {
	Feature FeatureID
	Signal  Signal
	Points  Points
}

type Decision struct {
	Confidence float64
	Verdict    Verdict
	Reasons    []MatchReason
}

type Weight struct {
	Agree    Points
	Disagree Points
}

type Thresholds struct {
	Merge  Points
	Review Points
}

type Scorer interface {
	ID() ScorerID
	Version() Version
	Score(a, b Record) Decision
}

type Weighted struct {
	features   []Feature
	weights    map[FeatureID]Weight
	thresholds Thresholds
}

func NewWeighted(features []Feature, weights map[FeatureID]Weight, thresholds Thresholds) (Weighted, error) {
	if thresholds.Review <= 0 || thresholds.Merge <= thresholds.Review || thresholds.Merge > maxPoints {
		return Weighted{}, fmt.Errorf("%w: thresholds %+v", ErrInvalidScorer, thresholds)
	}
	for _, feature := range features {
		weight, ok := weights[feature.ID()]
		if !ok || weight.Agree < 0 || weight.Disagree > 0 {
			return Weighted{}, fmt.Errorf("%w: weight of %s", ErrInvalidScorer, feature.ID())
		}
	}
	return Weighted{features: features, weights: weights, thresholds: thresholds}, nil
}

// TODO: веса и пороги стартовые, подобраны без данных. Их нужно откалибровать
// на размеченном корпусе через bench/ и менять только вместе с версией скорера.
func DefaultWeights() map[FeatureID]Weight {
	return map[FeatureID]Weight{
		FeatureVuln:      {Agree: 500, Disagree: -400},
		FeatureComponent: {Agree: 350, Disagree: -500},
		FeaturePath:      {Agree: 200},
		FeatureCode:      {Agree: 400, Disagree: -100},
		FeatureLine:      {Agree: 100, Disagree: -400},
		FeatureRule:      {Agree: 250},
		FeatureCWE:       {Agree: 50},
		FeatureSeverity:  {Disagree: -50},
		FeatureToolUID:   {Agree: 800},
	}
}

func DefaultThresholds() Thresholds {
	return Thresholds{Merge: 800, Review: 550}
}

func DefaultWeighted() (Weighted, error) {
	return NewWeighted(DefaultFeatures(), DefaultWeights(), DefaultThresholds())
}

func (Weighted) ID() ScorerID {
	return weightedID
}

func (Weighted) Version() Version {
	return weightedVersion
}

func (w Weighted) Score(a, b Record) Decision {
	if a.Kind != b.Kind {
		return Decision{Verdict: VerdictSeparate, Reasons: []MatchReason{{Feature: FeatureKind, Signal: SignalDisagree}}}
	}
	var (
		total   Points
		reasons []MatchReason
	)
	for _, feature := range w.features {
		signal := feature.Compare(a, b)
		if signal == SignalUnknown {
			continue
		}
		points := w.points(feature.ID(), signal)
		total += points
		reasons = append(reasons, MatchReason{Feature: feature.ID(), Signal: signal, Points: points})
	}
	total = min(max(total, 0), maxPoints)
	return Decision{Confidence: float64(total) / float64(maxPoints), Verdict: w.verdict(total), Reasons: reasons}
}

func (w Weighted) points(feature FeatureID, signal Signal) Points {
	if signal == SignalAgree {
		return w.weights[feature].Agree
	}
	return w.weights[feature].Disagree
}

func (w Weighted) verdict(total Points) Verdict {
	switch {
	case total >= w.thresholds.Merge:
		return VerdictMerge
	case total >= w.thresholds.Review:
		return VerdictReview
	default:
		return VerdictSeparate
	}
}
