# moqt-dissector

Media over QUIC Transport Wireshark Dissector (lua)

Pre-alpha not working post dissector for Media over QUIC Transport

Requires QUIC secret-key log file.

python3 aiomoqt/examples/sub_example.py --host fb.mvfst.net --port 9448 --endpoint "moq-relay"  --namespace "live/test" --trackname track --debug --keylogfile /tmp/moqt-secrets.txt

python3 aiomoqt/examples/pub_example.py --host fb.mvfst.net --port 9448 --endpoint "moq-relay"  --namespace "live/test" --trackname track --debug  --keylogfile /tmp/moqt-secrets.txt

tshark -X lua_script:moqt.lua -V -n -i eno2 -f "udp port 9448"  -o "tls.keylog_file:/tmp/moqt-secrets.txt"
