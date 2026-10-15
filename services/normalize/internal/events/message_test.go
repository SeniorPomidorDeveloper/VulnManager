package events

import (
	"testing"

	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/protobuf/proto"

	normalizev1 "vulnmanager/api/gen/go/vulnmanager/normalize/v1"
	"vulnmanager/modules/model"
)

func TestBuildMessage(t *testing.T) {
	scope, err := model.NewScope("acme", "payments", "prod")
	if err != nil {
		t.Fatal(err)
	}

	msg, err := buildMessage(Event{RunID: "run-1", Scope: scope, Tool: "trivy", ScanID: "scan-1"})
	if err != nil {
		t.Fatal(err)
	}

	var got normalizev1.ImportCompleted
	if err := proto.Unmarshal(msg.publishing.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetImportRunId() != "run-1" || got.GetTool() != "trivy" || got.GetScanId() != "scan-1" {
		t.Fatalf("unexpected body: %+v", &got)
	}
	if got.GetScope().GetTenantId() != "acme" || got.GetScope().GetProductId() != "payments" || got.GetScope().GetContextId() != "prod" {
		t.Fatalf("unexpected scope: %+v", got.GetScope())
	}
	if msg.routingKey != string(scope.Key()) {
		t.Fatalf("routing key = %q, want %q", msg.routingKey, scope.Key())
	}
	if msg.publishing.DeliveryMode != amqp.Persistent || msg.publishing.MessageId != "run-1" {
		t.Fatalf("unexpected delivery properties: %+v", msg.publishing)
	}
	if msg.publishing.Headers[headerSchema] != schemaName || msg.publishing.Headers[headerSchemaVersion] != schemaVersion {
		t.Fatalf("unexpected headers: %v", msg.publishing.Headers)
	}
}
