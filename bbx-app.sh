#!/data/data/com.termux/files/usr/bin/bash
cd ~/bbx
pgrep -f "ollama serve" >/dev/null || (nohup ollama serve >/dev/null 2>&1 &)
pgrep -f "http.server 8080" >/dev/null || (nohup python -m http.server 8080 >/dev/null 2>&1 &)
sleep 2
termux-open-url http://localhost:8080/bbx.html
