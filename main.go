package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/InspectorGadget/kybu/config"
	"github.com/InspectorGadget/kybu/constants"
	"github.com/InspectorGadget/kybu/structs"
	"github.com/InspectorGadget/kybu/variables"
	"github.com/gin-gonic/gin"
)

func main() {
	portPtr := flag.String("web-port", "8080", "Port for the web dashboard")
	flag.Parse()

	// 1. Enable CSM Globally on Startup
	if err := config.ToggleCSM(true); err != nil {
		fmt.Printf("Could not update config: %v\n", err)
	} else {
		fmt.Println("Kybu: CSM Enabled globally in '~/.aws/config'")
	}

	// 2. Ensure Cleanup on Exit (Ctrl+C)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nShutting down... Restoring AWS config.")
		config.ToggleCSM(false)
		os.Exit(0)
	}()

	// Start Background Workers
	go udpListener()
	go packetProcessor()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.SetTrustedProxies(nil)

	r.GET(
		"/",
		func(c *gin.Context) {
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(constants.HTML))
		},
	)
	r.GET("/ws", wsHandler)

	fmt.Printf("Kybu Dashboard running at http://localhost:%s\n", *portPtr)
	r.Run(":" + *portPtr)
}

// packetProcessor handles the forensic scraping and state updates
func packetProcessor() {
	for packet := range variables.PacketChan {
		service := strings.ToLower(packet.Service)
		region := packet.Region
		api := packet.Api
		iamAction := service + ":" + api

		if mapped, ok := variables.ApiMapping[iamAction]; ok {
			iamAction = mapped
		}

		fullMsg := fmt.Sprintf("%s %s %s %s",
			packet.AwsExceptionMessage, packet.Message, packet.ErrorMessage, packet.AwsException)

		var eventResources []string

		// 1. Standard ARN Scraper
		arnMatches := variables.ReArn.FindAllString(fullMsg, -1)
		for _, arn := range arnMatches {
			if !isIdentityArn(arn) {
				eventResources = append(eventResources, arn)
			}
		}

		// 2. Heuristic Scraper (If ARNs failed)
		if len(eventResources) == 0 {
			// DynamoDB
			reTable := regexp.MustCompile(`Table:\s+([a-zA-Z0-9._-]+)`)
			if match := reTable.FindStringSubmatch(fullMsg); len(match) > 1 {
				eventResources = append(eventResources, fmt.Sprintf("arn:aws:dynamodb:%s:*:table/%s", region, match[1]))
			}

			// S3 Improved (Skip "specified", "the", etc.)
			reS3 := regexp.MustCompile(`(?:s3://|bucket\s+)([a-zA-Z0-9.-]+)`)
			if match := reS3.FindStringSubmatch(fullMsg); len(match) > 1 {
				candidate := strings.Trim(match[1], ".")
				// Filter out common error message noise
				noise := map[string]bool{"specified": true, "the": true, "does": true, "not": true}
				if !noise[strings.ToLower(candidate)] {
					eventResources = append(eventResources, fmt.Sprintf("arn:aws:s3:::%s", candidate))
				}
			}
		}

		// 3. Update Global State
		variables.Policy.Lock()
		if _, exists := variables.Policy.Data[iamAction]; !exists {
			variables.Policy.Data[iamAction] = make(map[string]bool)
		}

		// --- THE CRITICAL FIX: The Purge ---
		// If we found a real resource, delete the wildcard for this action
		if len(eventResources) > 0 {
			delete(variables.Policy.Data[iamAction], "*")
		} else if len(variables.Policy.Data[iamAction]) == 0 {
			// Only add wildcard if we have NO specific resources yet
			eventResources = append(eventResources, "*")
		}

		for _, res := range eventResources {
			finalRes := applyServiceRules(iamAction, res)
			variables.Policy.Data[iamAction][finalRes] = true
		}
		jsonOutput := generateJSON()
		variables.Policy.Unlock()

		// --- UI Logic ---
		isDenied := packet.HttpStatusCode >= 400 || (packet.ErrorCode != "" && strings.Contains(packet.ErrorCode, "Denied"))
		colorClass := ""
		if isDenied {
			colorClass = "denied"
		}

		logEntry := fmt.Sprintf(
			`<div class="entry %s">[%s] <b>%s</b><br><span class="res">%s</span></div>`,
			colorClass, time.Now().Format("15:04:05"), iamAction, strings.Join(eventResources, ", "))

		broadcast(structs.WSUpdate{LogHTML: logEntry, PolicyJSON: jsonOutput})
	}
}

// isIdentityArn returns true if the ARN belongs to an IAM principal rather than a resource
func isIdentityArn(arn string) bool {
	identityMarkers := []string{":iam::", ":sts::", ":user/", ":role/", "assumed-role/"}
	for _, marker := range identityMarkers {
		if strings.Contains(arn, marker) {
			return true
		}
	}
	return false
}

func applyServiceRules(action string, arn string) string {
	if !strings.HasPrefix(action, "s3:") || arn == "*" {
		return arn
	}

	// List of actions that apply to objects (require /*)
	objectActions := []string{"GetObject", "PutObject", "DeleteObject", "AbortMultipartUpload"}
	isObjectAction := false
	for _, oa := range objectActions {
		if strings.Contains(action, oa) {
			isObjectAction = true
			break
		}
	}

	// If it's an object action but looks like a bucket ARN, add /*
	if isObjectAction && !strings.Contains(arn, "/") {
		return strings.TrimSuffix(arn, "/") + "/*"
	}

	// For bucket-level actions (like ListBucket), ensure we DON'T have a / or /*
	bucketActions := []string{"ListBucket", "GetBucketLocation"}
	for _, ba := range bucketActions {
		if strings.Contains(action, ba) {
			return strings.Split(arn, "/")[0]
		}
	}

	return arn
}

func generateJSON() string {
	type Statement struct {
		Sid      string   `json:"Sid"`
		Effect   string   `json:"Effect"`
		Action   []string `json:"Action"`
		Resource []string `json:"Resource"`
	}
	type Policy struct {
		Version   string      `json:"Version"`
		Statement []Statement `json:"Statement"`
	}

	groups := make(map[string]*Statement)

	for action, resources := range variables.Policy.Data {
		prefix := strings.Split(action, ":")[0]
		if _, ok := groups[prefix]; !ok {
			groups[prefix] = &Statement{
				Sid:      "Allow" + strings.ToUpper(prefix),
				Effect:   "Allow",
				Action:   []string{},
				Resource: []string{},
			}
		}

		if !slices.Contains(groups[prefix].Action, action) {
			groups[prefix].Action = append(groups[prefix].Action, action)
		}

		for res := range resources {
			if !slices.Contains(groups[prefix].Resource, res) {
				groups[prefix].Resource = append(groups[prefix].Resource, res)
			}
		}
	}

	final := Policy{
		Version:   "2012-10-17",
		Statement: []Statement{},
	}

	var prefixes []string
	for p := range groups {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	for _, p := range prefixes {
		stmt := groups[p]
		sort.Strings(stmt.Action)
		sort.Strings(stmt.Resource)
		final.Statement = append(final.Statement, *stmt)
	}

	bytes, _ := json.MarshalIndent(final, "", "    ")
	return string(bytes)
}

func udpListener() {
	addr, _ := net.ResolveUDPAddr("udp", ":31000")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()
	buf := make([]byte, 16384)

	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		var p structs.CSMPacket
		if json.Unmarshal(buf[:n], &p) == nil {
			variables.PacketChan <- p
		}
	}
}

func wsHandler(c *gin.Context) {
	conn, err := variables.Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	variables.ClientsLock.Lock()
	variables.Clients[conn] = true
	variables.Policy.RLock()
	currentJSON := generateJSON()
	variables.Policy.RUnlock()
	conn.WriteJSON(structs.WSUpdate{LogHTML: "", PolicyJSON: currentJSON})
	variables.ClientsLock.Unlock()

	defer func() {
		variables.ClientsLock.Lock()
		delete(variables.Clients, conn)
		variables.ClientsLock.Unlock()
		conn.Close()
	}()

	for {
		var cmd structs.WSCommand
		if err := conn.ReadJSON(&cmd); err != nil {
			break
		}
		if cmd.Action == "reset" {
			variables.Policy.Lock()
			variables.Policy.Data = make(map[string]map[string]bool)
			emptyJSON := generateJSON()
			variables.Policy.Unlock()
			broadcast(structs.WSUpdate{LogHTML: "RESET_SIGNAL", PolicyJSON: emptyJSON})
		}
	}
}

func broadcast(msg structs.WSUpdate) {
	variables.ClientsLock.Lock()
	defer variables.ClientsLock.Unlock()
	for client := range variables.Clients {
		client.WriteJSON(msg)
	}
}
