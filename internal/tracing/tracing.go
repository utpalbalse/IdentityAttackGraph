// Package tracing wires OpenTelemetry distributed tracing. When telemetry.otel_endpoint is set,
// spans are exported via OTLP/gRPC to a collector; otherwise tracing is a no-op (the global
// provider is left unset, so otel.Tracer returns a no-op tracer with negligible overhead). This
// keeps the default/demo path dependency-light while making production traces a config flip.
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Init configures the global tracer provider for a service. The returned shutdown func is always
// non-nil and flushes pending spans. When endpoint is empty, tracing is disabled and shutdown is a
// no-op.
func Init(ctx context.Context, service, version, endpoint string) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if endpoint == "" {
		return noop, nil
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(), // in-cluster collector; front with TLS at the mesh/ingress
	)
	if err != nil {
		return noop, fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", service),
		attribute.String("service.version", version),
	))
	if err != nil {
		res = resource.Default()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	return tp.Shutdown, nil
}

// Tracer returns a named tracer from the global provider.
func Tracer(name string) trace.Tracer { return otel.Tracer(name) }
