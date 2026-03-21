package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/InspectorGadget/kybu/config"
	"github.com/InspectorGadget/kybu/constants"
	"github.com/InspectorGadget/kybu/network"
	"github.com/InspectorGadget/kybu/structs"
	"github.com/InspectorGadget/kybu/variables"
	"github.com/gin-gonic/gin"
)

var debugCSM bool

func main() {
	portPtr := flag.String("web-port", "8080", "Port for the web dashboard")
	versionPtr := flag.Bool("version", false, "Print version and exit")
	debugCSMPtr := flag.Bool("debug-csm", false, "Show raw CSM packets and parsed details in the dashboard stream")
	flag.Parse()
	debugCSM = *debugCSMPtr

	// 1. Version Check
	if *versionPtr {
		fmt.Printf("Kybu %s\n", variables.Version)
		return
	}

	// 2. Pre-flight Port Check (Fail before touching AWS config)
	if err := network.CheckPortAvailability(*portPtr); err != nil {
		fmt.Printf("Error: Port %s is already in use.\n", *portPtr)
		fmt.Println("Please stop the process using that port or try: kybu --web-port 9090")
		return
	}

	// 3. Enable CSM Globally
	if err := config.ToggleCSM(true); err != nil {
		fmt.Printf("Could not update config: %v\n", err)
	} else {
		fmt.Println("Kybu: CSM Enabled globally in '~/.aws/config'")
	}

	// 4. Setup Cleanup Listener (Platform Agnostic)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n   Restoring AWS config...")
		config.ToggleCSM(false)
		os.Exit(0)
	}()

	// 5. Initialize Web Server in Background
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

	go func() {
		if err := r.Run(":" + *portPtr); err != nil {
			fmt.Printf("Web Server failed: %v\n", err)
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(os.Interrupt)
		}
	}()

	// 6. Verify and Announce
	fmt.Printf("Waiting for Kybu dashboard to initialize on port %s...\n", *portPtr)
	time.Sleep(500 * time.Millisecond)

	if network.VerifyServerIsUp(*portPtr) {
		fmt.Printf("Dashboard is LIVE at http://localhost:%s\n", *portPtr)
		fmt.Println("Listening for AWS telemetry (Ctrl+C to stop)...")
		if debugCSM {
			fmt.Println("Kybu: CSM debug mode is enabled (--debug-csm)")
		}
	} else {
		fmt.Println("  Warning: Dashboard unreachable. Triggering cleanup.")
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(os.Interrupt)
	}

	// 7. Start Background Workers
	go udpListener()

	// 8. Block on Packet Processor (Keeps main alive)
	packetProcessor()
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

		snippets, cliArgs := normalizeErrorSnippets(packet)
		if len(snippets) == 0 {
			snippets = []string{
				strings.TrimSpace(packet.AwsExceptionMessage),
				strings.TrimSpace(packet.Message),
				strings.TrimSpace(packet.ErrorMessage),
				strings.TrimSpace(packet.AwsException),
			}
		}
		fullMsg := strings.TrimSpace(strings.Join(snippets, " "))
		if fullMsg == "" {
			fullMsg = fmt.Sprintf("%s %s %s %s",
				packet.AwsExceptionMessage, packet.Message, packet.ErrorMessage, packet.AwsException)
		}

		if inferred := inferActionFromCliArgs(cliArgs); inferred != "" {
			iamAction = inferred
		}
		iamAction = inferActionFromError(fullMsg, iamAction)

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
			if match := reTableName.FindStringSubmatch(fullMsg); len(match) > 1 {
				eventResources = append(eventResources, fmt.Sprintf("arn:aws:dynamodb:%s:*:table/%s", region, match[1]))
			}

			// S3 Improved
			if match := reS3FromMessage.FindStringSubmatch(fullMsg); len(match) > 1 {
				candidate := strings.Trim(match[1], ".")
				noise := map[string]bool{"specified": true, "the": true, "does": true, "not": true}
				if !noise[strings.ToLower(candidate)] {
					eventResources = append(eventResources, fmt.Sprintf("arn:aws:s3:::%s", candidate))
				}
			}

			if match := reS3BucketNameText.FindStringSubmatch(fullMsg); len(match) > 1 {
				eventResources = append(eventResources, fmt.Sprintf("arn:aws:s3:::%s", strings.Trim(match[1], ".")))
			}

			if match := reS3BucketNameJSON.FindStringSubmatch(fullMsg); len(match) > 1 {
				eventResources = append(eventResources, fmt.Sprintf("arn:aws:s3:::%s", strings.Trim(match[1], ".")))
			}

			if match := reS3BucketNameLoose.FindStringSubmatch(fullMsg); len(match) > 1 {
				eventResources = append(eventResources, fmt.Sprintf("arn:aws:s3:::%s", strings.Trim(match[1], ".")))
			}
		}

		if argResources := deriveResourcesFromCliArgs(cliArgs, region); len(argResources) > 0 {
			eventResources = append(eventResources, argResources...)
		}
		if rawResources := deriveResourcesFromRawPacket(packet.RawPacket); len(rawResources) > 0 {
			eventResources = append(eventResources, rawResources...)
		}
		if len(eventResources) == 0 {
			if historyResources := deriveResourcesFromShellHistory(iamAction); len(historyResources) > 0 {
				eventResources = append(eventResources, historyResources...)
			}
		}
		eventResources = uniqueStrings(eventResources)
		suppressWildcard := shouldSuppressWildcard(iamAction, eventResources)

		// 3. Update Global State
		variables.Policy.Lock()
		policyUpdated := false
		if !(len(eventResources) == 0 && suppressWildcard) {
			if _, exists := variables.Policy.Data[iamAction]; !exists {
				variables.Policy.Data[iamAction] = make(map[string]bool)
			}

			if len(eventResources) > 0 {
				delete(variables.Policy.Data[iamAction], "*")
			} else if len(variables.Policy.Data[iamAction]) == 0 {
				eventResources = append(eventResources, "*")
			}

			for _, res := range eventResources {
				finalRes := applyServiceRules(iamAction, res)
				variables.Policy.Data[iamAction][finalRes] = true
			}
			policyUpdated = true
		}
		jsonOutput := generateJSON()
		variables.Policy.Unlock()

		if debugCSM {
			rawPacket := strings.TrimSpace(packet.RawPacket)
			if rawPacket == "" {
				reEncoded, _ := json.MarshalIndent(packet, "", "  ")
				rawPacket = string(reEncoded)
			}

			displayResources := strings.Join(eventResources, ", ")
			if displayResources == "" {
				displayResources = "(none)"
			}

			detail := fmt.Sprintf(
				"raw_packet=%s\nparsed_snippets=%s\ncli_args=%s\ninferred_action=%s\ninferred_resources=%s\nsuppress_wildcard=%t\npolicy_updated=%t",
				rawPacket,
				strings.Join(snippets, " | "),
				strings.Join(cliArgs, " | "),
				iamAction,
				displayResources,
				suppressWildcard,
				policyUpdated,
			)

			debugLogEntry := fmt.Sprintf(
				`<div class="entry"><b>[DEBUG CSM]</b><pre class="res">%s</pre></div>`,
				html.EscapeString(detail),
			)

			broadcast(
				structs.WSUpdate{
					LogHTML:    debugLogEntry,
					PolicyJSON: jsonOutput,
				},
			)
		}

		// --- UI Logic ---
		isDenied := packet.HttpStatusCode >= 400 || (packet.ErrorCode != "" && strings.Contains(packet.ErrorCode, "Denied"))
		colorClass := ""
		if isDenied {
			colorClass = "denied"
		}

		logEntry := fmt.Sprintf(
			`<div class="entry %s">[%s] <b>%s</b><br><span class="res">%s</span></div>`,
			colorClass, time.Now().Format("15:04:05"), iamAction, renderResources(eventResources, suppressWildcard))

		broadcast(
			structs.WSUpdate{
				LogHTML:    logEntry,
				PolicyJSON: jsonOutput,
			},
		)
	}
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
			p.RawPacket = strings.TrimSpace(string(buf[:n]))
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
