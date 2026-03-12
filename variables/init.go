package variables

import (
	"net/http"
	"regexp"
	"sync"

	"github.com/InspectorGadget/kybu/structs"
	"github.com/gorilla/websocket"
)

var (
	Version = "0.0.1"
	Policy  = structs.PolicyStore{
		Data: make(map[string]map[string]bool),
	}
	Upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	PacketChan  = make(chan structs.CSMPacket)
	Clients     = make(map[*websocket.Conn]bool)
	ClientsLock sync.Mutex

	ReAction   = regexp.MustCompile(`perform: ([\w:-]+)`)
	ReArn      = regexp.MustCompile(`arn:aws:[a-zA-Z0-9-]:[a-zA-Z0-9-]:[a-z0-9-]*:[0-9]{0,12}:[a-zA-Z0-9-_:/.]+`)
	ApiMapping = map[string]string{
		"s3:ListBuckets":   "s3:ListAllMyBuckets",
		"s3:ListObjectsV2": "s3:ListBucket",
	}
	IdentityMarkers = []string{":iam::", ":sts::", ":user/", ":role/", "assumed-role/"}
	S3ObjectActions = map[string]bool{
		"s3:GetObject":                true,
		"s3:PutObject":                true,
		"s3:DeleteObject":             true,
		"s3:AbortMultipartUpload":     true,
		"s3:ListMultipartUploadParts": true,
		"s3:RestoreObject":            true,
		"s3:PutObjectAcl":             true,
		"s3:GetObjectAcl":             true,
	}
)
