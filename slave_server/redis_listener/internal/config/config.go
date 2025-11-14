package config

import (
    "os"
    "time"

    "gopkg.in/yaml.v2"
)

type Config struct {
    App    AppConfig    `yaml:"app"`
    Redis  RedisConfig  `yaml:"redis"`
    Server ServerConfig `yaml:"server"`
}

type AppConfig struct {
    Name     string `yaml:"name"`
    Version  string `yaml:"version"`
    LogLevel string `yaml:"log_level"`
}

type RedisConfig struct {
    Addr       string   `yaml:"addr"`
    Password   string   `yaml:"password"`
    DB         int      `yaml:"db"`
    KeyPatterns []string `yaml:"key_patterns"`
    KeyPrefixes []string `yaml:"key_prefixes"`
}

type ServerConfig struct {
    MaxRetries          int           `yaml:"max_retries"`
    RetryInterval       time.Duration `yaml:"retry_interval_seconds"`
    ShutdownTimeout     time.Duration `yaml:"shutdown_timeout_seconds"`
}

// Load 从YAML文件加载配置
func Load(configPath string) (*Config, error) {
    data, err := os.ReadFile(configPath)
    if err != nil {
        return nil, err
    }
    
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    
    // 设置默认值
    if cfg.Server.ShutdownTimeout == 0 {
        cfg.Server.ShutdownTimeout = 30 * time.Second
    }
    
    return &cfg, nil
}