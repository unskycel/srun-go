package service

import (
	"context"
	"strings"
	"time"

	"srun/internal/protocol/srun"
)

// NetworkService provides local adapter enumeration, socket routing, and gateway probing.
type NetworkService struct{}

func NewNetworkService() *NetworkService {
	return &NetworkService{}
}

func (s *NetworkService) GetLocalIPv4List() ([]string, error) {
	return srun.GetLocalIPv4List()
}

func (s *NetworkService) ProbeGateway(ctx context.Context, gatewayHost string) (*srun.GatewayProbeSummary, error) {
	return srun.ProbeGatewayInterfaces(ctx, gatewayHost, 3*time.Second)
}

func (s *NetworkService) NormalizeIPToken(val any) string {
	if val == nil {
		return ""
	}
	if str, ok := val.(string); ok {
		clean := strings.TrimSpace(str)
		if clean == "" || strings.EqualFold(clean, "null") || strings.EqualFold(clean, "default") || strings.EqualFold(clean, "auto") || strings.EqualFold(clean, "undefined") {
			return ""
		}
		return clean
	}
	return ""
}
