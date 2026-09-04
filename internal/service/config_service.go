package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"srun/internal/domain/event"
	"srun/internal/domain/model"
	"srun/internal/platform/windows"
	"srun/internal/protocol/srun"
)

const (
	ConfigDirName  = "srun"
	ConfigFileName = "config.json"
)

// ConfigService manages application configuration persistence and encryption.
type ConfigService struct {
	mu       sync.RWMutex
	cfg      *model.Config
	eventBus *event.Bus
}

func NewConfigService(bus *event.Bus) *ConfigService {
	svc := &ConfigService{
		cfg:      model.DefaultConfig(),
		eventBus: bus,
	}
	_ = svc.Load()
	return svc
}

func GetConfigFilePath() (string, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		appData = filepath.Join(home, "AppData", "Roaming")
	}
	dir := filepath.Join(appData, ConfigDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFileName), nil
}

func (s *ConfigService) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath, err := GetConfigFilePath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		s.cfg = model.DefaultConfig()
		return nil
	}

	var cfg model.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		s.cfg = model.DefaultConfig()
		return nil
	}

	// Validate active IP against local network adapters
	availIPs, _ := srun.GetLocalIPv4List()
	if cfg.ActiveIP != nil {
		found := false
		for _, ip := range availIPs {
			if ip == *cfg.ActiveIP {
				found = true
				break
			}
		}
		if !found {
			cfg.ActiveIP = nil
		}
	}

	s.cfg = &cfg
	return nil
}

func (s *ConfigService) Save() error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	filePath, err := GetConfigFilePath()
	if err != nil {
		return err
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return err
	}

	if s.eventBus != nil {
		s.eventBus.Publish(event.Event{
			Type:    event.EventConfigChanged,
			Payload: s.GetConfigCopy(),
		})
	}
	return nil
}

func (s *ConfigService) Reset() error {
	s.mu.Lock()
	s.cfg = model.DefaultConfig()
	s.mu.Unlock()

	_ = windows.SetAutoStart(false, "")
	return s.Save()
}

func (s *ConfigService) GetConfigCopy() model.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.cfg
}

func (s *ConfigService) Update(fn func(c *model.Config)) error {
	s.mu.Lock()
	fn(s.cfg)
	s.mu.Unlock()
	return s.Save()
}
