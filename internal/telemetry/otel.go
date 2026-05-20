package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	attrServiceName    = "service.name"
	attrServiceVersion = "service.version"
)

// Provider holds initialized OTel tracer and meter.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	Tracer         trace.Tracer
	Meter          metric.Meter
}

func New(serviceName, serviceVersion string) (*Provider, error) {
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"",
			attribute.String(attrServiceName, serviceName),
			attribute.String(attrServiceVersion, serviceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create otel resource: %w", err)
	}

	traceExp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("create trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)

	metricExp, err := stdoutmetric.New()
	if err != nil {
		return nil, fmt.Errorf("create metric exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)

	return &Provider{
		tracerProvider: tp,
		meterProvider:  mp,
		Tracer:         tp.Tracer(serviceName),
		Meter:          mp.Meter(serviceName),
	}, nil
}

func (p *Provider) Shutdown(ctx context.Context) error {
	if err := p.tracerProvider.Shutdown(ctx); err != nil {
		return fmt.Errorf("tracer provider shutdown: %w", err)
	}
	if err := p.meterProvider.Shutdown(ctx); err != nil {
		return fmt.Errorf("meter provider shutdown: %w", err)
	}
	return nil
}
