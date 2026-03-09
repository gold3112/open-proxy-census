package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Workers struct {
		PortScanner int `yaml:"port_scanner"`
		ProxyTester int `yaml:"proxy_tester"`
		Analyzer    int `yaml:"analyzer"`
	} `yaml:"workers"`

	Targets struct {
		Sources []string `yaml:"sources"`
		CIDRs   []string `yaml:"cidrs"`
		Ports   []int    `yaml:"ports"`
	} `yaml:"targets"`

	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
