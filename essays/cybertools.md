---
layout: essay
type: essay
title: "Cybersecurity Tools (Mostly Free)"
# All dates must be YYYY-MM-DD format!
date: 2023-09-06
published: true
labels:
  - Cybersecurity
  - Tools
  - Kali
---
## Tool List
The following list is assembled to provide a helpful introduction to the tools used in various cybersecurity roles. (1) It is not comprehensive! Kali Linux (below) has over 600 tools installed in its default installtion configuration. This list is just a teaser! (2) If you see (KALI) behind the name of a tool, that means it is on the distribution of Kali Linux as of the date of this article. (3) Disclaimer: Don't abuse a tool for purposes it was not intended. Ethical hacking only, please! (4) The list is in alphabetical order, not type, usage or distribution. (5) If you aren't sure what you need, try starting with Kali.

---

### 1. Aircrack-ng (KALI) (FREE)
[Aircrack-ng](https://www.aircrack-ng.org/) is a complete suite of tools focusing on different aspects of WiFi security. Aircrack-ng focuses on monitoring, attacking, testing, and cracking your Wi-Fi network. It can perform packet capture (and export of data to text files for further processing by third party tools) and replay attacks, deauthentication, spoof access points via packet injection, check WiFi cards and driver capabilities (capture and injection), and crack WEP and WPA PSK (WPA 1 and 2) passwords.

### 2. Burp Suite (PAID) (some FREE)
[Burp](https://portswigger.net/burp) is a suite of tools specifically focused on debugging and testing the security of web applications. While the free version includes some great tools (web crawling, Repeater, Decoder, Sequencer, and Comparer), the power comes in at the Pro version with its ability to orchestrate custom attacks (Burp Intruder), Web vulnerability scanner, and Pro-exclusive BApp extensions. This makes it possible to creatively analyze a web app's attack vectors from all angles -- a key reason it's often ranked as one of the best cybersecurity tools. The community version of [Burp Suite](https://portswigger.net/burp/communitydownload) is free.

### 3. Defendify (PAID) (some FREE)
[Defendify](https://www.defendify.com/) is an all-in-one cybersecutiry platform with 13 modules in one platform backed by trusted cybersecurity advisors and 24/7 monitoring. They even offer up to $1 million in financial assistance for qualified cyber events through the Defendify Cybersecurity Service Warranty. You can take on the full package or any one of their three subsections: Detection and Response (active monitoring, detection, containment, and response), Policies and Training (set clear expectations and delivering ongoing cybersecurity education), and Assessment and Testing (mitigate cyber risk by actively identifying and addressing vulnerabilities across people, process, and technology). They offer some free tools as well, like  Cybersecurity Assessments, Vulnerability Scanning, and Threat Alerts/Notifications.

### 4. Gophish (FREE)
[Gophish](https://getgophish.com/) is a powerful, easy-to-use, open-source phishing toolkit meant to help pentesters and businesses conduct real-world phishing simulations. The idea behind gophish is simple – make industry-grade phishing training available to everyone. Affordable – Gophish is open-source software that is completely free for anyone to use. Accessible – Gophish is written in the Go programming language. This has the benefit that gophish releases are compiled binaries with no dependencies. In a nutshell, this makes installation as simple as "download and run"! The best way to know if your users will not fall for phishing attacks is to educate them and then test them!

### 5. Have I Been Pwned (FREE)
Created by award-winning cybersecurity professional Troy Hunt, [Have I Been Pwned](https://haveibeenpwned.com/) is a website where you enter your email address to check if your address has been revealed in a data breach. Have I Been Pwned's database is filled with billions of usernames, passwords, email addresses and other information that hackers have stolen and published online. This is a free resource for anyone to quickly assess if they may have been put at risk due to an online account of theirs having been compromised or "pwned" in a data breach. Simple to use, just enter your address in the search box, and entirely free.

### 6. Kali Linux (FREE)
[Kali Linux](https://www.kali.org/) is a Debian Linux derivative specifically designed toward testing for security tasks, such as penetration testing, security auditing and digital forensics. Kali includes roughly 600 pre-installed programs or [tools](https://www.kali.org/tools/all-tools/), each included to help computer security experts carry out a specific attack, probe or exploit against a target. Aircrack-ng, Metasploit , Nmap, Nikto, Sqlmap, and Wireshark are a few of the pre-installed tools that ship with the Kali Linux download.

### 7. Metasploit Framework (KALI) (FREE)
The Metasploit Framework (MSF) is far more than just a collection of exploits–it is also a solid foundation that you can build upon and easily customize to meet your needs. MSF is one of the most useful security auditing tools freely available to security professionals today. 

From a wide array of commercial grade exploits and an extensive exploit development environment, all the way to network information gathering tools and web vulnerability plugins, the Metasploit Framework can test computer system vulnerabilities or can be used to break into remote systems, used by both ethical hackers and criminal gangs to probe networks and applications for flaws and weaknesses. There is both a free and a Pro version and ships with more than 2,300 exploits and more than 3,300 modules and payloads to help users orchestrate well-planned attacks. [Metasploit](https://www.metasploit.com/) comes pre-installed on Kali Linux.

### 8. Nmap (KALI) (FREE)
[Nmap](https://nmap.org/) ("Network Mapper") is a free and open source utility for network discovery and security auditing. Useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime, Nmap uses raw IP packets to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. While Nmap provides users immense power and capability to explore networks, the program has a rather steep learning curve to get over before one becomes truly proficient in using it.

### 9. Nikto (KALI) (FREE)
[Nikto](https://cirt.net/Nikto2) is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers. It also checks for server configuration items such as the presence of multiple index files, HTTP server options, and will attempt to identify installed web servers and software. Scan items and plugins are frequently updated and can be automatically updated. Nikto is not designed as a stealthy tool. It will test a web server in the quickest time possible, and is obvious in log files or to an IPS/IDS. However, there is support for LibWhisker's anti-IDS methods in case you want to give it a try (or test your IDS system).

### 10. Open Vulnerability Assessment Scanner (FREE)
[OpenVAS](https://openvas.org/) is a full-featured vulnerability scanner. Its capabilities include unauthenticated and authenticated testing, various high-level and low-level internet and industrial protocols, performance tuning for large-scale scans and a powerful internal programming language to implement any type of vulnerability test. 

The scanner obtains the tests for detecting vulnerabilities from a feed that has a long history and daily updates. OpenVAS has been developed Greenbone and, as part of the commercial vulnerability management product family Greenbone Enterprise Appliance, the scanner forms the Greenbone Community Edition together with other open-source modules.

### 11. OSSEC (FREE)
[OSSEC](https://www.ossec.net/) is a scalable, multi-platform, open source, free Host-based Intrusion Detection System (HIDS) that's been touted as one of the most popular systems for intrusion detection and prevention. OSSEC has a powerful correlation and analysis engine, integrating log analysis, file integrity monitoring, Windows registry monitoring, centralized policy enforcement, rootkit detection, real-time alerting and active response. It runs on most operating systems, including Linux, OpenBSD, FreeBSD, MacOS, Solaris and Windows.

### 12. P0f (FREE)
[P0f](https://lcamtuf.coredump.cx/p0f3/) is a steath tool that utilizes an array of sophisticated, purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications without interfering in any way. Some of p0f's capabilities include:

- Highly scalable and extremely fast identification of the OS and software on both endpoints of a vanilla TCP connection - especially in settings where NMap probes are blocked, too slow, unreliable, or would simply set off alarms.

- Measurement of system uptime and network hookup, distance (including topology behind NAT or packet filters), user language preferences, and so on.

- Automated detection of connection sharing / NAT, load balancing, and application-level proxying setups.

- Detection of clients and servers that forge declarative statements such as X-Mailer or User-Agent.

- The tool can be operated in the foreground or as a daemon, and offers a simple real-time API for third-party components that wish to obtain additional information about the actors they are talking to.

Common uses for p0f include reconnaissance during penetration tests; routine network monitoring; detection of unauthorized network interconnects in corporate environments; providing signals for abuse-prevention tools; and miscellanous forensics. Being passive rather than active means p0f is nearly impossible to detect and even harder to block, making it a favorite tool for ethical hackers and cybercriminals alike.

### 13. PfSense (FREE)
The [pfSense](https://www.pfsense.org/) project is a free network firewall distribution, based on the FreeBSD operating system with a custom kernel and including third party free software packages for additional functionality. pfSense software, with the help of the package system, is able to provide the same functionality or more of common commercial firewalls, without any of the artificial limitations. PfSense can also be configured for intrusion detection and prevention, traffic shaping, load balancing and content filtering. pfSense software includes a web interface for the configuration of all included components.

### 14. REMnux (FREE)
[REMnux](https://docs.remnux.org/) a Linux toolkit for reverse-engineering and analyzing malicious software. REMnux provides a curated collection of free tools to analyze Windows executables, reverse-engineer binaries and inspect suspicious documents. It also includes a collection of free tools cybersecurity professionals can use to monitor networks, gather data and conduct memory forensics. It has a total of 6,700 known exploits covering a range of servers.

### 15. Security Onion (PAID)
[Security Onion](https://securityonionsolutions.com/) is an open source software collection based on the Linux kernel that helps cybersecurity professionals develop a comprehensive profile of their system's security posture, threat hunting, network security monitoring, and log management. Security Onion includes best-of-breed free and open tools including Suricata, Zeek, the Elastic Stack and many others. The overarching goal of the project is to offer teams a foolproof security monitoring solution that reduces decision paralysis and false alerts.

### 16. Snort (PAID)
[Snort](https://www.snort.org/) is an open source network intrusion prevention system (IPS) and intrusion detection system (IDS) capable of real-time traffic analysis and logging. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generates alerts for users. Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike.

### 17. Sqlmap (KALI) (FREE)
[Sqlmap](https://sqlmap.org/) is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

### 18. VeraCrypt (FREE)
[VeraCrypt](https://www.veracrypt.fr/en/Home.html) is a free open source disk encryption software package. It runs on Windows, Mac OSX and Linux and creates a virtual encrypted disk within a file before mounting it as a real disk. On-the-fly encryption means that data is automatically encrypted right before it is saved and decrypted right after it is loaded, without any user intervention. No data stored on an encrypted volume can be read (decrypted) without using the correct password/keyfile(s) or correct encryption keys. Entire file system is encrypted (e.g., file names, folder names, contents of every file, free space, meta data, etc).

Files can be copied to and from a mounted VeraCrypt volume just like they are copied to/from any normal disk (for example, by simple drag-and-drop operations). Files are automatically being decrypted on the fly (in memory/RAM) while they are being read or copied from an encrypted VeraCrypt volume. Similarly, files that are being written or copied to the VeraCrypt volume are automatically being encrypted on the fly (right before they are written to the disk) in RAM. Note that this does not mean that the whole file that is to be encrypted/decrypted must be stored in RAM before it can be encrypted/decrypted. There are no extra memory (RAM) requirements for VeraCrypt. 

### 19. Wireshark (KALI) (FREE)
[Wireshark](https://www.wireshark.org/) is considered by many to be the world's most popular network protocol analyzer and an indispensable tool to locate, identify and examine network packets to diagnose critical issues and spot security weaknesses. The website for Wireshark outlines its broad set of features and provides a user's guide and other resources for putting this free cybersecurity tool to best use.

### 20. Zed Attack Proxy (FREE)
[ZAP](https://www.zaproxy.org/) is an open source penetration testing tool designed specifically for testing web applications. It is known as a "man-in-the-middle proxy,” where it intercepts and inspects messages sent between browsers and web applications. ZAP provides functionality for developers, testers new to security testing and security testing specialists. There are also versions for each major operating system and Docker. Additional functionality is available via add-ons in the ZAP Marketplace.