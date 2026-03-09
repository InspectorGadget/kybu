package structs

import (
	"sync"

	"github.com/gorilla/websocket"
)

// CSMPacket represents the telemetry data sent by the AWS SDK
type CSMPacket struct {
	Service             string `json:"Service"`
	Api                 string `json:"Api"`
	HttpStatusCode      int    `json:"HttpStatusCode"`
	ErrorCode           string `json:"ErrorCode"`
	ErrorMessage        string `json:"ErrorMessage"`
	Message             string `json:"Message"`
	AwsException        string `json:"AwsException"`
	AwsExceptionMessage string `json:"AwsExceptionMessage"`
	Region              string `json:"Region"`
	UserAgent           string `json:"UserAgent"`
}

// PolicyStore handles thread-safe storage of discovered permissions.
type PolicyStore struct {
	sync.RWMutex
	Data map[string]map[string]bool
}

// WSUpdate is the payload sent to the web dashboard via WebSockets
type WSUpdate struct {
	LogHTML    string `json:"log_html"`
	PolicyJSON string `json:"policy_json"`
}

// WSCommand represents instructions sent from the UI to the backend
type WSCommand struct {
	Action string `json:"action"`
}

// Hub (Optional/Future) could manage multiple websocket clients
type Hub struct {
	Clients    map[*websocket.Conn]bool
	Broadcast  chan WSUpdate
	Register   chan *websocket.Conn
	Unregister chan *websocket.Conn
}
