package events

import (
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/protobuf/proto"

	commonv1 "vulnmanager/api/gen/go/vulnmanager/common/v1"
	ingestv1 "vulnmanager/api/gen/go/vulnmanager/ingest/v1"
	"vulnmanager/services/ingest/internal/jobs"
)

const (
	contentType   = "application/x-protobuf"
	schemaName    = "vulnmanager.ingest.v1.ReportReceived"
	schemaVersion = int32(1)

	headerSchema        = "schema"
	headerSchemaVersion = "schema_version"
)

type message struct {
	routingKey string
	publishing amqp.Publishing
}

func buildMessage(event jobs.Event) (message, error) {
	body, err := proto.Marshal(&ingestv1.ReportReceived{
		RawKey: event.RawKey.String(),
		Scope: &commonv1.Scope{
			TenantId:  string(event.Scope.TenantID),
			ProductId: string(event.Scope.ProductID),
			ContextId: string(event.Scope.ContextID),
		},
		Tool:   string(event.Tool),
		ScanId: string(event.RawKey.ScanID),
		JobId:  event.JobID.String(),
	})
	if err != nil {
		return message{}, fmt.Errorf("encode report.received: %w", err)
	}
	return message{
		routingKey: string(event.Scope.Key()),
		publishing: amqp.Publishing{
			ContentType:  contentType,
			DeliveryMode: amqp.Persistent,
			MessageId:    event.JobID.String(),
			Headers: amqp.Table{
				headerSchema:        schemaName,
				headerSchemaVersion: schemaVersion,
			},
			Body: body,
		},
	}, nil
}
