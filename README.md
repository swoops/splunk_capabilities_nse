# splunk_capabilities_nse
NSE script to get a Splunk Forwarder's capabilities

# BETA Warning

This code is in a "testing" phase. I only released it publicly so others can
run it on SAFE environments and send feedback if things go wrong. I don't have
much confidence in the code, so you shouldn't either.

## example

```
# nmap -Pn -T4 127.0.0.1 -p 9997 --script ./splunk_capabilities.nse
Starting Nmap 7.92 ( https://nmap.org  ) at 2022-04-06 14:26 EDT
Nmap scan report for localhost (127.0.0.1)
	Host is up (0.000063s latency).

	PORT     STATE SERVICE
	9997/tcp open  Splunk Reciver Port
	| splunk_capabilities: 
	|       cap_response -> success
	|       cap_flush_key -> true
	|       idx_can_send_hb -> true
	|       idx_can_recv_token -> true
	|       v4 -> true
	|       channel_limit -> 300
	|_      pl -> 6

	Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds
```
