package events

import (
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/protobuf/proto"

	commonv1 "vulnmanager/api/gen/go/vulnmanager/common/v1"
	normalizev1 "vulnmanager/api/gen/go/vulnmanager/normalize/v1"
)

const (
	contentType   = "application/x-protobuf"
	schemaName    = "vulnmanager.normalize.v1.ImportCompleted"
	schemaVersion = int32(1)

	headerSchema        = "schema"
	headerSchemaVersion = "schema_version"
)

type message struct {
	routingKey string
	publishing amqp.Publishing
}

func buildMessage(event Event) (message, error) {
	body, err := proto.Marshal(&normalizev1.ImportCompleted{
		ImportRunId: string(event.RunID),
		Scope: &commonv1.Scope{
			TenantId:  string(event.Scope.TenantID),
			ProductId: string(event.Scope.ProductID),
			ContextId: string(event.Scope.ContextID),
		},
		Tool:   string(event.Tool),
		ScanId: string(event.ScanID),
	})
	if err != nil {
		return message{}, fmt.Errorf("encode import.completed: %w", err)
	}
	return message{
		routingKey: string(event.Scope.Key()),
		publishing: amqp.Publishing{
			ContentType:  contentType,
			DeliveryMode: amqp.Persistent,
			MessageId:    string(event.RunID),
			Headers: amqp.Table{
				headerSchema:        schemaName,
				headerSchemaVersion: schemaVersion,
			},
			Body: body,
		},
	}, nil
}
