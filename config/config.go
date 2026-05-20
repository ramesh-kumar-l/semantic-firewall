package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Audit     AuditConfig     `mapstructure:"audit"`
	Policy    PolicyConfig    `mapstructure:"policy"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
}

type ServerConfig struct {
	Host             string `mapstructure:"host"`
	Port             int    `mapstructure:"port"`
	ReadTimeoutMs    int    `mapstructure:"read_timeout_ms"`
	WriteTimeoutMs   int    `mapstructure:"write_timeout_ms"`
	InspectTimeoutMs int    `mapstructure:"inspect_timeout_ms"`
	MaxPromptBytes   int    `mapstructure:"max_prompt_bytes"`
}

type AuditConfig struct {
	Path string `mapstructure:"path"`
}

type PolicyConfig struct {
	DefaultAction string  `mapstructure:"default_action"`
	DenyThreshold float64 `mapstructure:"deny_threshold"`
}

type TelemetryConfig struct {
	ServiceName    string `mapstructure:"service_name"`
	ServiceVersion string `mapstructure:"service_version"`
	ExporterType   string `mapstructure:"exporter_type"`
}

func Load(path string) (*Config, error) {
	v := viper.New()

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout_ms", 5000)
	v.SetDefault("server.write_timeout_ms", 5000)
	v.SetDefault("server.inspect_timeout_ms", 500)
	v.SetDefault("server.max_prompt_bytes", 65536)
	v.SetDefault("audit.path", "audit.jsonl")
	v.SetDefault("policy.default_action", "allow")
	v.SetDefault("policy.deny_threshold", 0.8)
	v.SetDefault("telemetry.service_name", "semantic-firewall")
	v.SetDefault("telemetry.service_version", "0.1.0")
	v.SetDefault("telemetry.exporter_type", "stdout")

	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}
