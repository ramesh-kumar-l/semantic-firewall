package telemetry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	prometheusexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
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

// Config holds telemetry initialization options.
type Config struct {
	ServiceName     string
	ServiceVersion  string
	TraceExporter   string // "stdout" (default) or "otlp"
	MetricsExporter string // "prometheus" (default) or "stdout"
	OTLPEndpoint    string // used when TraceExporter == "otlp"
}

// Provider holds initialized OTel tracer and meter.
type Provider struct {
	Tracer         trace.Tracer
	Meter          metric.Meter
	MetricsHandler http.Handler // non-nil when MetricsExporter == "prometheus"
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
}

func New(cfg Config) (*Provider, error) {
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"",
			attribute.String(attrServiceName, cfg.ServiceName),
			attribute.String(attrServiceVersion, cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create otel resource: %w", err)
	}

	tp, err := buildTracerProvider(cfg, res)
	if err != nil {
		return nil, err
	}

	mp, metricsHandler, err := buildMeterProvider(cfg, res)
	if err != nil {
		return nil, err
	}

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)

	return &Provider{
		Tracer:         tp.Tracer(cfg.ServiceName),
		Meter:          mp.Meter(cfg.ServiceName),
		MetricsHandler: metricsHandler,
		tracerProvider: tp,
		meterProvider:  mp,
	}, nil
}

func buildTracerProvider(cfg Config, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	if cfg.TraceExporter == "otlp" {
		exp, err := otlptracehttp.New(
			context.Background(),
			otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
			otlptracehttp.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("create otlp trace exporter: %w", err)
		}
		return sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		), nil
	}

	exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("create stdout trace exporter: %w", err)
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	), nil
}

func buildMeterProvider(cfg Config, res *resource.Resource) (*sdkmetric.MeterProvider, http.Handler, error) {
	if cfg.MetricsExporter != "stdout" {
		exp, err := prometheusexporter.New()
		if err != nil {
			return nil, nil, fmt.Errorf("create prometheus exporter: %w", err)
		}
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(exp),
			sdkmetric.WithResource(res),
		)
		return mp, promhttp.Handler(), nil
	}

	exp, err := stdoutmetric.New()
	if err != nil {
		return nil, nil, fmt.Errorf("create stdout metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
		sdkmetric.WithResource(res),
	)
	return mp, nil, nil
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
