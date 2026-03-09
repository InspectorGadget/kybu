package constants

const HTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Ricochet</title>
    <style>
        body { font-family: 'Consolas', monospace; background: #0b0b1a; color: #00ffcc; padding: 20px; display: flex; height: 95vh; margin: 0; gap: 20px; }
        #left-col { width: 35%; display: flex; flex-direction: column; border-right: 1px solid #333; padding-right: 20px; }
        #right-col { width: 65%; display: flex; flex-direction: column; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 10px; }
        h3 { margin: 0; color: #fff; }
        button { background: #238636; color: white; border: none; padding: 5px 12px; cursor: pointer; border-radius: 4px; font-family: inherit; }
        button:hover { background: #2ea043; }
        button.clear { background: #da3633; }
        button.clear:hover { background: #f85149; }
        #logs { flex-grow: 1; overflow-y: auto; background: #000; padding: 10px; border: 1px solid #333; }
        pre { background: #000; border: 1px solid #00ffcc; padding: 20px; color: #fff; border-radius: 8px; flex-grow: 1; overflow: auto; margin: 0; }
        .denied { color: #ff3333; }
        .entry { border-bottom: 1px solid #1a1a1a; padding: 8px 0; font-size: 12px; }
        .res { color: #888; font-size: 11px; }
        #toast { visibility: hidden; min-width: 250px; margin-left: -125px; background-color: #333; color: #fff; text-align: center; border-radius: 4px; padding: 16px; position: fixed; z-index: 1; left: 50%; bottom: 30px; border: 1px solid #00ffcc; }
        #toast.show { visibility: visible; animation: fadein 0.5s, fadeout 0.5s 2.5s; }
        @keyframes fadein { from {bottom: 0; opacity: 0;} to {bottom: 30px; opacity: 1;} }
        @keyframes fadeout { from {bottom: 30px; opacity: 1;} to {bottom: 0; opacity: 0;} }
    </style>
</head>
<body>
    <div id="left-col">
        <div class="header">
            <h3>Ricochet Stream</h3>
            <button class="clear" onclick="resetBackend()">Clear Stream</button>
        </div>
        <div id="logs"></div>
    </div>
    <div id="right-col">
        <div class="header">
            <h3>Generated Policy</h3>
            <button onclick="copyPolicy()">Copy JSON</button>
        </div>
        <pre id="policy-out"></pre>
    </div>
    <div id="toast">Notification</div>

    <script>
        const logs = document.getElementById('logs');
        const policyOut = document.getElementById('policy-out');
        const ws = new WebSocket("ws://" + location.host + "/ws");

        ws.onmessage = (e) => {
            const data = JSON.parse(e.data);

            if (data.policy_json) {
                policyOut.innerText = data.policy_json;
            }

            if (data.log_html === "RESET_SIGNAL") {
                logs.innerHTML = "";
                showToast("Backend State Cleared!");
            } else if (data.log_html) {
                const isScrolledToBottom = logs.scrollHeight - logs.scrollTop === logs.clientHeight;
                
                const div = document.createElement('div');
                div.innerHTML = data.log_html;
                logs.prepend(div.firstChild);
            }
        };

        function resetBackend() {
            ws.send(
                JSON.stringify(
                    {action: "reset"}
                )
            );
        }

        function copyPolicy() {
            navigator.clipboard.writeText(policyOut.innerText).then(
                () => {
                    showToast("Policy copied!");
                },
            );
        }

        function showToast(msg) {
            const x = document.getElementById("toast");
            x.innerText = msg;
            x.className = "show";
            setTimeout(
                () => {
                    x.className = x.className.replace("show", "");
                }, 
                3000
            );
        }
    </script>
</body>
</html>
`
