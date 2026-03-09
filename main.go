package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/InspectorGadget/ricochet/config"
	"github.com/InspectorGadget/ricochet/constants"
	"github.com/InspectorGadget/ricochet/structs"
	"github.com/InspectorGadget/ricochet/variables"
	"github.com/gin-gonic/gin"
)

func main() {
	portPtr := flag.String("web-port", "8080", "Port for the web dashboard")
	flag.Parse()

	// 1. Enable CSM Globally on Startup
	if err := config.ToggleCSM(true); err != nil {
		fmt.Printf("Could not update config: %v\n", err)
	} else {
		fmt.Println("CSM Enabled globally in '~/.aws/config'")
	}

	// 2. Ensure Cleanup on Exit (Ctrl+C)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nShutting down... Removing CSM flags.")

		// This runs the removal logic
		config.ToggleCSM(false)

		os.Exit(0)
	}()

	// Goroutine for listeners
	go udpListener()
	go packetProcessor()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.SetTrustedProxies(nil)

	r.GET(
		"/",
		func(c *gin.Context) {
			c.Data(
				http.StatusOK,
				"text/html; charset=utf-8",
				[]byte(constants.HTML),
			)
		},
	)
	r.GET("/ws", wsHandler)

	r.Run(":" + *portPtr)
}

// Process packets and update global state
func packetProcessor() {
	for packet := range variables.PacketChan {
		service := strings.ToLower(packet.Service)
		api := packet.Api
		iamAction := service + ":" + api
		resource := "*"

		// Apply Mapping
		if mapped, ok := variables.ApiMapping[iamAction]; ok {
			iamAction = mapped
		}

		// Detect Failure
		isDenied := packet.HttpStatusCode >= 400 || (packet.ErrorCode != "" && strings.Contains(packet.ErrorCode, "Denied"))
		fullMsg := packet.AwsExceptionMessage + " " + packet.Message

		// Apply Smart Regex Scraper (Server-Side)
		if len(fullMsg) > 5 {
			// Find hidden action
			if matches := variables.ReAction.FindStringSubmatch(fullMsg); len(matches) > 1 {
				iamAction = matches[1]
			}

			// Find hidden Resources
			arnMatches := variables.ReArn.FindAllString(fullMsg, -1)
			for _, arn := range arnMatches {
				// Filter out identities
				if !strings.Contains(arn, ":iam::") && !strings.Contains(arn, ":sts::") && !strings.Contains(arn, ":user/") && !strings.Contains(arn, ":role/") {
					resource = arn
					break
				}
			}
		}

		// 2. Update State
		variables.Policy.Lock()
		if _, exists := variables.Policy.Data[iamAction]; !exists {
			variables.Policy.Data[iamAction] = make(map[string]bool)
		}
		variables.Policy.Data[iamAction][resource] = true
		jsonOutput := generateJSON()
		variables.Policy.Unlock()

		// 3. Create Log HTML (Server renders the HTML fragment)
		colorClass := ""
		deniedText := ""
		if isDenied {
			colorClass = "denied"
			deniedText = " (DENIED)"
		}

		logEntry := fmt.Sprintf(
			`<div class="entry %s">[%s] <b>%s</b>%s<br><span class="res">%s</span></div>`,
			colorClass,
			time.Now().Format("3:04:05 PM"),
			iamAction,
			deniedText,
			resource,
		)

		// 4. Broadcast to UI
		broadcast(
			structs.WSUpdate{
				LogHTML:    logEntry,
				PolicyJSON: jsonOutput,
			},
		)
	}
}

// Generate the final Grouped IAM Policy JSON
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

	// Group by Service Prefix
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

		groups[prefix].Action = append(groups[prefix].Action, action)

		// Add resources (avoid duplicates in slice)
		for res := range resources {
			exists := slices.Contains(groups[prefix].Resource, res)
			if !exists {
				groups[prefix].Resource = append(groups[prefix].Resource, res)
			}
		}
	}

	// Build Final Struct
	final := Policy{
		Version:   "2012-10-17",
		Statement: []Statement{},
	}

	// Sort Keys for deterministic output
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

	// Send current state immediately upon connection
	variables.Policy.RLock()
	currentJSON := generateJSON()
	variables.Policy.RUnlock()
	conn.WriteJSON(
		structs.WSUpdate{
			LogHTML:    "",
			PolicyJSON: currentJSON,
		},
	)
	variables.ClientsLock.Unlock()

	defer func() {
		variables.ClientsLock.Lock()
		delete(variables.Clients, conn)
		variables.ClientsLock.Unlock()
		conn.Close()
	}()

	// Listen for commands (e.g. Reset)
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

			// Broadcast reset to everyone
			broadcast(
				structs.WSUpdate{
					LogHTML:    "RESET_SIGNAL",
					PolicyJSON: emptyJSON,
				},
			)
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
