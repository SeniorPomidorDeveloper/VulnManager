package events

import (
	"context"
	"errors"
	"fmt"
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"
)

type (
	URL          string
	ExchangeName string
)

const exchangeKind = "x-consistent-hash"

var (
	ErrUnroutable = errors.New("events: message is not routed to any queue")
	ErrNotAcked   = errors.New("events: broker did not confirm the message")
)

type Config struct {
	URL      URL
	Exchange ExchangeName
}

type AMQPPublisher struct {
	cfg Config

	mu      sync.Mutex
	conn    *amqp.Connection
	channel *amqp.Channel
	returns chan amqp.Return
}

func NewAMQPPublisher(cfg Config) *AMQPPublisher {
	return &AMQPPublisher{cfg: cfg}
}

func (p *AMQPPublisher) Publish(ctx context.Context, event Event) error {
	msg, err := buildMessage(event)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.channel == nil || p.channel.IsClosed() {
		if err := p.connect(); err != nil {
			return err
		}
	}
	if err := p.publish(ctx, msg); err != nil {
		p.dropChannel()
		return err
	}
	return nil
}

func (p *AMQPPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func (p *AMQPPublisher) publish(ctx context.Context, msg message) error {
	confirmation, err := p.channel.PublishWithDeferredConfirmWithContext(
		ctx, string(p.cfg.Exchange), msg.routingKey, true, false, msg.publishing,
	)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	acked, err := confirmation.WaitContext(ctx)
	if err != nil {
		return fmt.Errorf("wait confirmation: %w", err)
	}
	select {
	case <-p.returns:
		return ErrUnroutable
	default:
	}
	if !acked {
		return ErrNotAcked
	}
	return nil
}

func (p *AMQPPublisher) connect() error {
	p.dropChannel()
	conn, err := amqp.Dial(string(p.cfg.URL))
	if err != nil {
		return fmt.Errorf("dial broker: %w", err)
	}
	channel, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("open channel: %w", err)
	}
	if err := channel.ExchangeDeclare(string(p.cfg.Exchange), exchangeKind, true, false, false, false, nil); err != nil {
		_ = conn.Close()
		return fmt.Errorf("declare exchange: %w", err)
	}
	if err := channel.Confirm(false); err != nil {
		_ = conn.Close()
		return fmt.Errorf("enable confirms: %w", err)
	}
	p.conn, p.channel = conn, channel
	p.returns = channel.NotifyReturn(make(chan amqp.Return, 1))
	return nil
}

func (p *AMQPPublisher) dropChannel() {
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.conn, p.channel, p.returns = nil, nil, nil
}
