# MITM-HTTP-
Ever wondered what a Man-in-the-Middle (MITM) attack looks like under the hood? 👇

I built a modular MITM tool in Python that simulates how an attacker can silently sit between a victim and the router, intercept traffic, and tamper with what the user sees on the network.​​

🔍 What this lab tool does

ARP spoofing: Poisons the ARP cache so the victim routes traffic through the attacker’s machine.​​

DNS spoofing: Redirects selected domains (e.g. “login” or “update” portals) to a controlled IP using crafted DNS responses.​​

Packet sniffing: Captures IP/TCP flows, resolves hostnames, and enriches them with WHOIS data for better visibility.​​

Fake HTTP server: Serves a custom page from the attacker machine to demonstrate how users can be transparently redirected.​​

JSON logging: Stores all observed connections (src, dst, port, host, org, timestamp) for offline analysis.​

🎯 Why this matters
MITM attacks are still a common way to steal credentials, manipulate traffic, and downgrade secure connections, especially on insecure or shared networks. Building this as a lab project helped deepen understanding of how ARP, DNS, and routing really work beyond theory.​

🛡️ Defensive takeaways

Always enforce HTTPS and HSTS wherever possible.​

Use VPNs on untrusted networks to reduce exposure to local MITM attempts.​

Monitor for ARP anomalies and suspicious DNS responses inside internal networks.​

⚠️ Ethical note
This tool is strictly for controlled lab environments and authorized security testing only. Unauthorized use against systems you do not own or administer is illegal and unethical.​

If you are interested, I can share more about the architecture (threads, Scapy-based modules, and logging design) in a follow-up post.
