package pipetest

import (
	"context"
	"strconv"
	"testing"

	"vulnmanager/modules/pipeline"
)

type doubleAndStringify struct{}

func (doubleAndStringify) Run(_ context.Context, in int) (string, error) {
	return strconv.Itoa(in * 2), nil
}

func TestRunContractSuite_ExternalStage(t *testing.T) {
	RunContractSuite[int, string](t, func() pipeline.Stage[int, string] {
		return doubleAndStringify{}
	}, 21, "42")
}
