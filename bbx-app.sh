#!/data/data/com.termux/files/usr/bin/bash
cd ~/bbx
pgrep -f "ollama serve" >/dev/null || (nohup ollama serve >/dev/null 2>&1 &)
pgrep -f "bbx_server.py" >/dev/null || (nohup python bbx_server.py >/dev/null 2>&1 &)
sleep 2
termux-open-url http://localhost:8080/bbx.html
