package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"vulnmanager/modules/model"
	"vulnmanager/services/processing/internal/adapters"
	"vulnmanager/services/processing/internal/consumer"
	"vulnmanager/services/processing/internal/store"
	"vulnmanager/services/processing/internal/worker"
)

var errDown = errors.New("db down")

type failingTx struct {
	store.Tx
	err error
}

type failingStore struct {
	err error
}

func (s failingStore) InTx(_ context.Context, fn func(store.Tx) error) error {
	return fn(failingTx{err: s.err})
}

func (t failingTx) Run(context.Context, model.TenantID, model.ImportRunID) (store.Run, error) {
	return store.Run{}, t.err
}

func newHandler(t *testing.T, err error) handler {
	t.Helper()
	registry, regErr := adapters.Builtin()
	if regErr != nil {
		t.Fatal(regErr)
	}
	w, workerErr := worker.New(failingStore{err: err}, registry)
	if workerErr != nil {
		t.Fatal(workerErr)
	}
	return handler{worker: w, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestHandlerMarksMissingRunAsPermanent(t *testing.T) {
	for _, cause := range []error{store.ErrRunNotFound, store.ErrRunNotCompleted} {
		err := newHandler(t, cause).Handle(context.Background(), consumer.Event{Tenant: "t", Run: "r"})
		if !errors.Is(err, consumer.ErrPermanent) || !errors.Is(err, cause) {
			t.Fatalf("%v: got %v", cause, err)
		}
	}
}

func TestHandlerKeepsOtherErrorsRetryable(t *testing.T) {
	err := newHandler(t, errDown).Handle(context.Background(), consumer.Event{Tenant: "t", Run: "r"})
	if !errors.Is(err, errDown) || errors.Is(err, consumer.ErrPermanent) {
		t.Fatalf("got %v", err)
	}
}
