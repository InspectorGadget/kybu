package structs

import "sync"

// Raw Telemetry from AWS SDK
type CSMPacket struct {
	Service             string `json:"Service"`
	Api                 string `json:"Api"`
	ErrorCode           string `json:"ErrorCode"`
	HttpStatusCode      int    `json:"HttpStatusCode"`
	AwsExceptionMessage string `json:"AwsExceptionMessage"`
	Message             string `json:"Message"`
}

// Message sent TO the frontend
type WSUpdate struct {
	LogHTML    string `json:"log_html"`
	PolicyJSON string `json:"policy_json"`
}

// Incoming Message FROM the frontend
type WSCommand struct {
	Action string `json:"action"` // e.g. "reset"
}

// Internal State Store (Thread-Safe)
type PolicyStore struct {
	sync.RWMutex
	Data map[string]map[string]bool // Action -> Set of Resources
}
