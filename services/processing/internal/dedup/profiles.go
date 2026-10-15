package dedup

import "vulnmanager/modules/model"

const (
	byKindID      ScorerID = "by-kind"
	byKindVersion Version  = 1
)

type ByKind struct {
	profiles map[model.Kind]Weighted
	fallback Weighted
}

func NewByKind(fallback Weighted, profiles map[model.Kind]Weighted) ByKind {
	return ByKind{profiles: profiles, fallback: fallback}
}

func (ByKind) ID() ScorerID {
	return byKindID
}

func (ByKind) Version() Version {
	return byKindVersion
}

func (s ByKind) Score(a, b Record) Decision {
	if profile, ok := s.profiles[a.Kind]; ok {
		return profile.Score(a, b)
	}
	return s.fallback.Score(a, b)
}

// TODO: веса профилей стартовые, подобраны без данных. Их нужно откалибровать
// на размеченном корпусе через bench/ и менять только вместе с версией скорера.
func DefaultByKind() (ByKind, error) {
	fallback, err := DefaultWeighted()
	if err != nil {
		return ByKind{}, err
	}
	tables := map[model.Kind]map[FeatureID]Weight{
		model.KindSCA:       dependencyWeights(),
		model.KindContainer: dependencyWeights(),
		model.KindSAST:      codeWeights(),
		model.KindSecret:    secretWeights(),
		model.KindIaC:       iacWeights(),
	}
	profiles := make(map[model.Kind]Weighted, len(tables))
	for kind, weights := range tables {
		profile, err := NewWeighted(DefaultFeatures(), complete(weights), DefaultThresholds())
		if err != nil {
			return ByKind{}, err
		}
		profiles[kind] = profile
	}
	return NewByKind(fallback, profiles), nil
}

func complete(weights map[FeatureID]Weight) map[FeatureID]Weight {
	full := make(map[FeatureID]Weight, len(weights))
	for _, feature := range DefaultFeatures() {
		full[feature.ID()] = weights[feature.ID()]
	}
	return full
}

func dependencyWeights() map[FeatureID]Weight {
	return map[FeatureID]Weight{
		FeatureVuln:      {Agree: 500, Disagree: -400},
		FeatureComponent: {Agree: 350, Disagree: -500},
		FeaturePath:      {Agree: 100},
		FeatureCWE:       {Agree: 50},
		FeatureSeverity:  {Disagree: -50},
	}
}

func codeWeights() map[FeatureID]Weight {
	return map[FeatureID]Weight{
		FeatureRule:     {Agree: 250},
		FeaturePath:     {Agree: 200},
		FeatureCode:     {Agree: 400, Disagree: -100},
		FeatureCWE:      {Agree: 50},
		FeatureSeverity: {Disagree: -50},
	}
}

func secretWeights() map[FeatureID]Weight {
	return map[FeatureID]Weight{
		FeatureRule:     {Agree: 300},
		FeaturePath:     {Agree: 300},
		FeatureCode:     {Agree: 300, Disagree: -100},
		FeatureSeverity: {Disagree: -50},
	}
}

func iacWeights() map[FeatureID]Weight {
	return map[FeatureID]Weight{
		FeatureRule:     {Agree: 350},
		FeaturePath:     {Agree: 250},
		FeatureCode:     {Agree: 250, Disagree: -100},
		FeatureCWE:      {Agree: 50},
		FeatureSeverity: {Disagree: -50},
	}
}
