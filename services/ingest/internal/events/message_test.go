package events

import (
	"testing"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/protobuf/proto"

	ingestv1 "vulnmanager/api/gen/go/vulnmanager/ingest/v1"
	"vulnmanager/modules/model"
	"vulnmanager/services/ingest/internal/jobs"
)

func TestBuildMessage(t *testing.T) {
	scope, err := model.NewScope("acme", "payments", "prod")
	if err != nil {
		t.Fatal(err)
	}
	jobID := uuid.New()

	msg, err := buildMessage(jobs.Event{
		JobID:  jobID,
		Scope:  scope,
		Tool:   "trivy",
		RawKey: model.RawKeyFor(scope, "scan-1", "abcd"),
	})
	if err != nil {
		t.Fatal(err)
	}

	var got ingestv1.ReportReceived
	if err := proto.Unmarshal(msg.publishing.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetJobId() != jobID.String() || got.GetRawKey() != "acme/scan-1/abcd" || got.GetTool() != "trivy" || got.GetScanId() != "scan-1" {
		t.Fatalf("unexpected body: %+v", &got)
	}
	if got.GetScope().GetTenantId() != "acme" || got.GetScope().GetProductId() != "payments" || got.GetScope().GetContextId() != "prod" {
		t.Fatalf("unexpected scope: %+v", got.GetScope())
	}
	if msg.routingKey != string(scope.Key()) {
		t.Fatalf("routing key = %q, want %q", msg.routingKey, scope.Key())
	}
	if msg.publishing.DeliveryMode != amqp.Persistent || msg.publishing.MessageId != jobID.String() {
		t.Fatalf("unexpected delivery properties: %+v", msg.publishing)
	}
	if msg.publishing.Headers[headerSchema] != schemaName || msg.publishing.Headers[headerSchemaVersion] != schemaVersion {
		t.Fatalf("unexpected headers: %v", msg.publishing.Headers)
	}
}
