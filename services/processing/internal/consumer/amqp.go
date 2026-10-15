package consumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type (
	URL          string
	ExchangeName string
	QueueName    string
)

const (
	exchangeKind   = "x-consistent-hash"
	bindingWeight  = "1"
	retrySuffix    = ".retry"
	deadSuffix     = ".dead"
	reconnectDelay = 5 * time.Second
	queueTypeKey   = "x-queue-type"
	queueTypeValue = "quorum"
)

var ErrNotConfirmed = errors.New("consumer: broker did not confirm the message")

var openSteps = []struct {
	name string
	run  func(*session) error
}{
	{"open consume channel", (*session).openConsumeChannel},
	{"open publish channel", (*session).openPublishChannel},
	{"enable confirms", (*session).enableConfirms},
	{"set prefetch", (*session).setPrefetch},
	{"declare topology", (*session).declareTopology},
}

var republishTargets = map[Verdict]func(*Consumer) QueueName{
	VerdictRetry: (*Consumer).retryQueue,
	VerdictDead:  (*Consumer).deadQueue,
}

type Config struct {
	URL         URL
	Exchange    ExchangeName
	Queue       QueueName
	Prefetch    int
	RetryDelay  time.Duration
	ConsumerTag string
}

type Consumer struct {
	cfg     Config
	handler Handler
	metrics *Metrics
	log     *slog.Logger
}

type session struct {
	consumer *Consumer
	conn     *amqp.Connection
	consume  *amqp.Channel
	publish  *amqp.Channel
}

func New(cfg Config, handler Handler, metrics *Metrics, log *slog.Logger) *Consumer {
	return &Consumer{cfg: cfg, handler: handler, metrics: metrics, log: log}
}

func (c *Consumer) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := c.runSession(ctx); err != nil {
			c.log.Error("consumer session ended", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(reconnectDelay):
		}
	}
}

func (c *Consumer) runSession(ctx context.Context) error {
	s, err := c.open()
	if err != nil {
		return err
	}
	defer s.close()

	deliveries, err := s.consume.Consume(string(c.cfg.Queue), c.cfg.ConsumerTag, false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}
	c.log.Info("consuming", "queue", c.cfg.Queue, "prefetch", c.cfg.Prefetch)

	closed := s.conn.NotifyClose(make(chan *amqp.Error, 1))
	inFlight := s.startWorkers(ctx, deliveries)
	return s.waitStop(ctx, closed, inFlight)
}

func (s *session) startWorkers(ctx context.Context, deliveries <-chan amqp.Delivery) *sync.WaitGroup {
	var inFlight sync.WaitGroup
	for range s.consumer.cfg.Prefetch {
		inFlight.Add(1)
		go func() {
			defer inFlight.Done()
			for delivery := range deliveries {
				s.settle(context.WithoutCancel(ctx), delivery)
			}
		}()
	}
	return &inFlight
}

func (s *session) waitStop(ctx context.Context, closed <-chan *amqp.Error, inFlight *sync.WaitGroup) error {
	select {
	case <-ctx.Done():
		_ = s.consume.Cancel(s.consumer.cfg.ConsumerTag, false)
		inFlight.Wait()
		return nil
	case closeErr := <-closed:
		inFlight.Wait()
		if closeErr != nil {
			return fmt.Errorf("connection closed: %w", closeErr)
		}
		return errors.New("connection closed")
	}
}

func (s *session) settle(ctx context.Context, delivery amqp.Delivery) {
	verdict := decide(ctx, s.consumer.handler, delivery.Body, s.consumer.log)
	s.consumer.metrics.messages.WithLabelValues(string(verdict)).Inc()

	if err := s.moveFor(ctx, verdict, delivery); err != nil {
		s.consumer.metrics.failures.WithLabelValues(string(verdict)).Inc()
		s.consumer.log.Error("cannot move message, returning it to the queue", "verdict", verdict, "error", err)
		_ = delivery.Nack(false, true)
		return
	}
	_ = delivery.Ack(false)
}

func (s *session) moveFor(ctx context.Context, verdict Verdict, delivery amqp.Delivery) error {
	target, move := republishTargets[verdict]
	if !move {
		return nil
	}
	return s.republish(ctx, target(s.consumer), delivery)
}

func (s *session) republish(ctx context.Context, queue QueueName, delivery amqp.Delivery) error {
	confirmation, err := s.publish.PublishWithDeferredConfirmWithContext(ctx, "", string(queue), false, false, amqp.Publishing{
		ContentType:  delivery.ContentType,
		DeliveryMode: amqp.Persistent,
		MessageId:    delivery.MessageId,
		Headers:      delivery.Headers,
		Body:         delivery.Body,
	})
	if err != nil {
		return fmt.Errorf("publish to %s: %w", queue, err)
	}
	acked, err := confirmation.WaitContext(ctx)
	if err != nil {
		return fmt.Errorf("confirm %s: %w", queue, err)
	}
	if !acked {
		return ErrNotConfirmed
	}
	return nil
}

func (c *Consumer) open() (*session, error) {
	conn, err := amqp.Dial(string(c.cfg.URL))
	if err != nil {
		return nil, fmt.Errorf("dial broker: %w", err)
	}
	s := &session{consumer: c, conn: conn}
	for _, step := range openSteps {
		if err := step.run(s); err != nil {
			s.close()
			return nil, fmt.Errorf("%s: %w", step.name, err)
		}
	}
	return s, nil
}

func (s *session) openConsumeChannel() (err error) {
	s.consume, err = s.conn.Channel()
	return err
}

func (s *session) openPublishChannel() (err error) {
	s.publish, err = s.conn.Channel()
	return err
}

func (s *session) enableConfirms() error {
	return s.publish.Confirm(false)
}

func (s *session) setPrefetch() error {
	return s.consume.Qos(s.consumer.cfg.Prefetch, 0, false)
}

func (s *session) declareTopology() error {
	return s.consumer.declare(s.consume)
}

func (c *Consumer) declare(ch *amqp.Channel) error {
	if err := ch.ExchangeDeclare(string(c.cfg.Exchange), exchangeKind, true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare exchange: %w", err)
	}
	queues := []struct {
		name QueueName
		args amqp.Table
	}{
		{c.cfg.Queue, amqp.Table{queueTypeKey: queueTypeValue}},
		{c.retryQueue(), amqp.Table{
			queueTypeKey:                queueTypeValue,
			"x-message-ttl":             c.cfg.RetryDelay.Milliseconds(),
			"x-dead-letter-exchange":    "",
			"x-dead-letter-routing-key": string(c.cfg.Queue),
		}},
		{c.deadQueue(), amqp.Table{queueTypeKey: queueTypeValue}},
	}
	for _, q := range queues {
		if _, err := ch.QueueDeclare(string(q.name), true, false, false, false, q.args); err != nil {
			return fmt.Errorf("declare queue %s: %w", q.name, err)
		}
	}
	if err := ch.QueueBind(string(c.cfg.Queue), bindingWeight, string(c.cfg.Exchange), false, nil); err != nil {
		return fmt.Errorf("bind queue: %w", err)
	}
	return nil
}

func (c *Consumer) retryQueue() QueueName {
	return c.cfg.Queue + retrySuffix
}

func (c *Consumer) deadQueue() QueueName {
	return c.cfg.Queue + deadSuffix
}

func (s *session) close() {
	_ = s.conn.Close()
}
