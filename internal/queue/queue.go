// Package queue is a thin NATS JetStream wrapper for NHIID's async job flow. The API publishes
// collection jobs; the worker consumes them durably (at-least-once, manual ack). If NATS is
// unavailable the caller degrades to running collection in-process, so the stack still works.
package queue

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// CollectJob is a collection request placed on the stream.
type CollectJob struct {
	Provider       string `json:"provider"`
	Account        string `json:"account"`
	Project        string `json:"project"`
	Fixture        string `json:"fixture"`
	RoleARN        string `json:"role_arn"`
	ExternalID     string `json:"external_id"`
	Region         string `json:"region"`
	GCPCredentials string `json:"gcp_credentials"`
	// repo (secret-scan report ingest)
	Report         string `json:"report"`
	Repo           string `json:"repo"`
	RepoProvider   string `json:"repo_provider"`
	RepoVisibility string `json:"repo_visibility"`
	// k8s (cluster export ingest)
	Cluster     string `json:"cluster"`
	K8sExport   string `json:"k8s_export"`
	RequestedBy string `json:"requested_by"`
}

type Queue struct {
	nc      *nats.Conn
	js      nats.JetStreamContext
	subject string
}

// Connect dials NATS and ensures the work-queue stream exists (idempotent).
func Connect(url, stream string) (*Queue, error) {
	nc, err := nats.Connect(url,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.Timeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	if _, err := js.StreamInfo(stream); err != nil {
		if _, err := js.AddStream(&nats.StreamConfig{
			Name:      stream,
			Subjects:  []string{stream + ".>"},
			Retention: nats.WorkQueuePolicy,
			MaxAge:    24 * time.Hour,
		}); err != nil {
			nc.Close()
			return nil, fmt.Errorf("add stream %q: %w", stream, err)
		}
	}
	return &Queue{nc: nc, js: js, subject: stream + ".collect"}, nil
}

func (q *Queue) Close() {
	if q != nil && q.nc != nil {
		_ = q.nc.Drain()
	}
}

// PublishCollect enqueues a collection job (persisted by JetStream).
func (q *Queue) PublishCollect(job CollectJob) error {
	b, _ := json.Marshal(job)
	_, err := q.js.Publish(q.subject, b)
	return err
}

// ConsumeCollect subscribes durably; handler errors Nak (redeliver), success Acks.
func (q *Queue) ConsumeCollect(durable string, handler func(CollectJob) error) error {
	_, err := q.js.Subscribe(q.subject, func(m *nats.Msg) {
		var j CollectJob
		if err := json.Unmarshal(m.Data, &j); err != nil {
			_ = m.Term() // unparseable — drop, don't redeliver
			return
		}
		if handler(j) != nil {
			_ = m.Nak()
			return
		}
		_ = m.Ack()
	}, nats.Durable(durable), nats.ManualAck(), nats.AckWait(5*time.Minute))
	return err
}
