package variables

import (
	"net/http"
	"regexp"
	"sync"

	"github.com/InspectorGadget/kybu/structs"
	"github.com/gorilla/websocket"
)

var (
	Version = "" // Will be injected at build time via -ldflags="-X github.com/InspectorGadget/kybu/variables.Version=$(VERSION)"
	Policy  = structs.PolicyStore{
		Data: make(map[string]map[string]bool),
	}
	Upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	PacketChan  = make(chan structs.CSMPacket)
	Clients     = make(map[*websocket.Conn]bool)
	ClientsLock sync.Mutex

	ReArn      = regexp.MustCompile(`arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:[a-zA-Z0-9-_:/.]+`)
	ApiMapping = map[string]string{
		"s3:ListBuckets":   "s3:ListAllMyBuckets",
		"s3:ListObjectsV2": "s3:ListBucket",
	}
)
