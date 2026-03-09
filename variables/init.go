package variables

import (
	"net/http"
	"regexp"
	"sync"

	"github.com/InspectorGadget/ricochet/structs"
	"github.com/gorilla/websocket"
)

var (
	Policy = structs.PolicyStore{
		Data: make(map[string]map[string]bool),
	}
	Upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	// Channels
	PacketChan = make(chan structs.CSMPacket)
	Clients    = make(
		map[*websocket.Conn]bool,
	)
	ClientsLock sync.Mutex

	// Regex & Mappings (Compiled once for speed)
	ReAction   = regexp.MustCompile(`perform: ([\w:-]+)`)
	ReArn      = regexp.MustCompile(`arn:aws:[a-zA-Z0-9-_:/]+`)
	ApiMapping = map[string]string{
		"s3:ListBuckets": "s3:ListAllMyBuckets",
	}
)
