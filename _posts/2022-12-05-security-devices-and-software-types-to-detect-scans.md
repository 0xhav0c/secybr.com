---
title: Security Devices and Software types to Detect Scans
categories: [red team, reconing]
tags: [security devices, attack detection mechanism, IDS, IPS, firewall, waf, red-team]
comments: true
---

Security Devices and Software types to Detect Scans are as follows:

1. IDS (**Intrusion Detection System**)
2. IPS (**Intrusion Prevention System**)
3. Firewall
4. WAF (Web Application Firewall)
5. SOC (Cyber Operation Center)

# IDS

![Diagram: Traffic flow of a hacker triggering an IDS solution](/assets/img/pitcures/red-team/security-devices.png)
_Diagram: Traffic flow of a hacker triggering an IDS solution_

An Intrusion Detection System (IDS) is a system that monitors network traffic for suspicious activity and issues alerts when such activity is discovered. It is a software application that scans a network or a system for the harmful activity or policy breaching. Any malicious venture or violation is normally reported either to an administrator or collected centrally using a security information and event management (SIEM) system.

Intrusion prevention systems also monitor network packets inbound the system to check the malicious activities involved in it and at once send the warning notifications. IDS are classified into 5 types:

## Network Intrusion Detection System (NIDS)

Network intrusion detection systems (NIDS) are set up at a planned point within the network to examine traffic from all devices on the network. It performs an observation of passing traffic on the entire subnet and matches the traffic that is passed on the subnets to the collection of known attacks. Once an attack is identified or abnormal behavior is observed, the alert can be sent to the administrator. An example of a NIDS is installing it on the subnet where firewalls are located in order to see if someone is trying to crack the firewall.

## Host Intrusion Detection System (HIDS)

Host intrusion detection systems (HIDS) run on independent hosts or devices on the network. A HIDS monitors the incoming and outgoing packets from the device only and will alert the administrator if suspicious or malicious activity is detected. It takes a snapshot of existing system files and compares it with the previous snapshot. If the analytical system files were edited or deleted, an alert is sent to the administrator to investigate. An example of HIDS usage can be seen on mission-critical machines, which are not expected to change their layout.

## Protocol-based Intrusion Detection System (PIDS)

Protocol-based intrusion detection system (PIDS) comprises a system or agent that would consistently resides at the front end of a server, controlling and interpreting the protocol between a user/device and the server. It is trying to secure the web server by regularly monitoring the HTTPS protocol stream and accept the related HTTP protocol. As HTTPS is un-encrypted and before instantly entering its web presentation layer then this system would need to reside in this interface, between to use the HTTPS.

## Application Protocol-based Intrusion Detection System (APIDS)

Application Protocol-based Intrusion Detection System (APIDS) is a system or agent that generally resides within a group of servers. It identifies the intrusions by monitoring and interpreting the communication on application-specific protocols. For example, this would monitor the SQL protocol explicit to the middleware as it transacts with the database in the web server.

## Hybrid Intrusion Detection System

Hybrid intrusion detection system is made by the combination of two or more approaches of the intrusion detection system. In the hybrid intrusion detection system, host agent or system data is combined with network information to develop a complete view of the network system. Hybrid intrusion detection system is more effective in comparison to the other intrusion detection system. Prelude is an example of Hybrid IDS.

## Detection Method of IDS

### Signature-based Method

Signature-based IDS detects the attacks on the basis of the specific patterns such as number of bytes or number of 1’s or number of 0’s in the network traffic. It also detects on the basis of the already known malicious instruction sequence that is used by the malware. The detected patterns in the IDS are known as signatures.
Signature-based IDS can easily detect the attacks whose pattern (signature) already exists in system but it is quite difficult to detect the new malware attacks as their pattern (signature) is not known.

### Anomaly-based Method

Anomaly-based IDS was introduced to detect unknown malware attacks as new malware are developed rapidly. In anomaly-based IDS there is use of machine learning to create a trustful activity model and anything coming is compared with that model and it is declared suspicious if it is not found in model. Machine learning-based method has a better-generalized property in comparison to signature-based IDS as these models can be trained according to the applications and hardware configurations**.**

# IPS

![Diagram: Traffic flow of a hacker triggering an IPS solution](/assets/img/pitcures/red-team/security-devices1.png)
_Diagram: Traffic flow of a hacker triggering an IPS solution_

Intrusion Prevention System is also known as Intrusion Detection and Prevention System. It is a network security application that monitors network or system activities for malicious activity. Major functions of intrusion prevention systems are to identify malicious activity, collect information about this activity, report it and attempt to block or stop it.

Intrusion prevention systems are contemplated as augmentation of Intrusion Detection Systems (IDS) because both IPS and IDS operate network traffic and system activities for malicious activity.

IPS typically record information related to observed events, notify security administrators of important observed events and produce reports. Many IPS can also respond to a detected threat by attempting to prevent it from succeeding. They use various response techniques, which involve the IPS stopping the attack itself, changing the security environment or changing the attack’s content. IPS are classified into 4 types:

## Network-based intrusion prevention system (NIPS)

It monitors the entire network for suspicious traffic by analyzing protocol activity.

## Wireless intrusion prevention system (WIPS)

It monitors a wireless network for suspicious traffic by analyzing wireless networking protocols.

## Network behavior analysis (NBA):

It examines network traffic to identify threats that generate unusual traffic flows, such as distributed denial of service attacks, specific forms of malware and policy violations.

## Host-based intrusion prevention system (HIPS):

It is an inbuilt software package which operates a single host for doubtful activity by scanning events that occur within that host.

# IDS vs IPS, what are the differences?

The IDS and IPS both analyze network packets and compare the contents to a known threat database. The key high-level difference is that an IDS is a monitoring system, while IPS is a control system.

An IDS doesn’t alter packets, it is a passive “listen-only” detection and monitoring solution that doesn’t take action on it’s own.

Where an IPS is a control system that accepts or rejects packets based on the ruleset, actively preventing packet delivery based on the contents, similar to a firewall preventing traffic by IP address.

IDS deployments do require admin staff or another system like a SIEM to analyze the results and take the appropriate action. The IDS cannot take automatic actions against hackers capable of exploiting these vulnerabilities once they enter the network, leaving the IDS inadequate for threat prevention. IDS typically are positioned as a post-mortem forensics tool for the SecOps or computer security incident response team (CSIRT) for security incident investigations.

The IPS, on the other hand, is designed to catch dangerous packets in the act and drop them before they reach their target. Acting on its own to make decisions, which requires regularly updating the database with new threat data.

There are a few things to note about both IDS and IPS they are only as effective as their threat databases, and need to be kept updated when new attacks break out.

And, why are these two different tools? The IDS was originally developed as a listen-only monitoring tool because the analysis required could not keep pace with the direct communications traffic of the network infrastructure. And that is where it has stayed, a forensics detection solution, while the IPS was developed to take it a step further to actively block.

Yes, there are vendors that provide both IDS and IPS functionality in one. There are solutions that have integrated IPS systems with firewalls creating a Unified Threat Management (UTM) technology. But both IDS and IPS have found their use as the go-to tools for Modern Security Stacks.

# Firewall

![Untitled](/assets/img/pitcures/red-team/security-devices2.png)

Firewalls prevent unauthorized access to networks through software or firmware. By utilizing a set of rules, the firewall examines and blocks incoming and outgoing traffic.

Fencing your property protects your house and keeps trespassers at bay; similarly, firewalls are used to secure a computer network. Firewalls are network security systems that prevent unauthorized access to a network. It can be a hardware or software unit that filters the incoming and outgoing traffic within a private network, according to a set of rules to spot and prevent cyberattacks.

The most important function of a firewall is that it creates a border between an external network and the guarded network where the firewall inspects all packets (pieces of data for internet transfer) entering and leaving the guarded network. Once the inspection is completed, a firewall can differentiate between benign and malicious packets with the help of a set of pre-configured rules.

The firewall abides such packets, whether they come in a rule set or not, so that they should not enter into the guarded network.

This packet form information includes the information source, its destination, and the content. These might differ at every level of the network, and so do the rule sets. Firewalls read these packets and reform them concerning rules to tell the protocol where to send them. 

A firewall can either be software or hardware. Software firewalls are programs installed on each computer, and they regulate network traffic through applications and port numbers. Meanwhile, hardware firewalls are the equipment established between the gateway and your network. Additionally, you call a firewall delivered by a cloud solution as a cloud firewall.

There are multiple types of firewalls based on their traffic filtering methods, structure, and functionality. A few of the types of firewalls are:

## Packet Filtering

A packet filtering firewall controls data flow to and from a network. It allows or blocks the data transfer based on the packet's source address, the destination address of the packet, the application protocols to transfer the data, and so on.

## Proxy Service Firewall

This type of firewall protects the network by filtering messages at the application layer. For a specific application, a proxy firewall serves as the gateway from one network to another.

## Stateful Inspection

Such a firewall permits or blocks network traffic based on state, port, and protocol. Here, it decides filtering based on administrator-defined rules and context.

## Next-Generation Firewall

According to Gartner, Inc.’s definition, the next-generation firewall is a deep-packet inspection firewall that adds application-level inspection, intrusion prevention, and information from outside the firewall to go beyond port/protocol inspection and blocking.

## Unified Threat Management (UTM) Firewall

A UTM device generally integrates the capabilities of a stateful inspection firewall, intrusion prevention, and antivirus in a loosely linked manner. It may include additional services and, in many cases, cloud management. UTMs are designed to be simple and easy to use.

## Threat-Focused NGFW

These firewalls provide advanced threat detection and mitigation. With network and endpoint event correlation, they may detect evasive or suspicious behavior.

# WAF

![Untitled](/assets/img/pitcures/red-team/security-devices3.png)

A web application firewall (WAF) protects web applications from a variety of application layer attacks such as cross-site scripting (XSS), SQL injection, and cookie poisoning, among others. Attacks to apps are the leading cause of breaches they are the gateway to your valuable data. With the right WAF in place, you can block the array of attacks that aim to exfiltrate that data by compromising your systems.

[https://youtu.be/p8CQcF_9280](https://youtu.be/p8CQcF_9280)

## How does a web application firewall (WAF) work?

A WAF protects your web apps by filtering, monitoring, and blocking any malicious HTTP/S traffic traveling to the web application, and prevents any unauthorized data from leaving the app. It does this by adhering to a set of policies that help determine what traffic is malicious and what traffic is safe. Just as a proxy server acts as an intermediary to protect the identity of a client, a WAF operates in similar fashion but in the reverse called a reverse proxy acting as an intermediary that protects the web app server from a potentially malicious client.

WAFs can come in the form of software, an appliance, or delivered as-a-service. Policies can be customized to meet the unique needs of your web application or set of web applications. Although many WAFs require you update the policies regularly to address new vulnerabilities, advances in machine learning enable some WAFs to update automatically.

## The difference between a web application firewall (WAF), an intrusion prevention system (IPS) and a next-generation firewall (NGFW)

An IPS is an intrusion prevention system, a WAF is a web application firewall, and an NGFW is a next-generation firewall. What’s the difference between them all?

An IPS is a more broadly focused security product. It is typically signature and policy based meaning it can check for well-known vulnerabilities and attack vectors based on a signature database and established policies. The IPS establishes a standard based off the database and policies, then sends alerts when any traffic deviates from the standard. The signatures and policies grow over time as new vulnerabilities are known. In general, IPS protects traffic across a range of protocol types such as DNS, SMTP, TELNET, RDP, SSH, and FTP. IPS typically operates and protects layers 3 and 4. The network and session layers although some may offer limited protection at the application layer (layer 7).

A web application firewall (WAF) protects the application layer and is specifically designed to analyze each HTTP/S request at the application layer. It is typically user, session, and application aware, cognizant of the web apps behind it and what services they offer. Because of this, you can think of a WAF as the intermediary between the user and the app itself, analyzing all communications before they reach the app or the user. Traditional WAFs ensure only allowed actions (based on security policy) can be performed. For many organizations, WAFs are a trusted, first line of defense for applications, especially to protect against the OWASP Top 10 the foundational list of the most seen application vulnerabilities. This Top 10 currently includes:

- Injection attacks
- Broken Authentication
- Sensitive data exposure
- XML External Entities (XXE)
- Broken Access control
- Security misconfigurations
- Cross Site Scripting (XSS)
- Insecure Deserialization

A next-generation firewall (NGFW) monitors the traffic going out to the Internet across web sites, email accounts, and SaaS. Simply put, it’s protecting the user (vs the web application). A NGFW will enforce user-based policies and adds context to security policies in addition to adding features such as URL filtering, anti-virus/anti-malware, and potentially its own intrusion prevention systems (IPS). While a WAF is typically a reverse proxy (used by servers), NGFWs are often forward proxys (used by clients such as a browser).

## WAF Security Models

WAFs can use a positive or negative security model, or a combination of the two:

- **Positive security model** the positive WAF security model involves a whitelist that filters traffic according to a list of permitted elements and actions anything not on the list is blocked. The advantage of this model is that it can block new or unknown attacks that the developer didn’t anticipate.
- **Negative security model** the negative model involves a blacklist that only blocks specific items anything not on the list is allowed. This model is easier to implement but it cannot guarantee that all threats are addressed. It also requires maintaining a potentially long list of malicious signatures. The level of security depends on the number of restrictions implemented.

## Types of Web Application Firewalls

- **Network-based WAF: U**sually hardware-based, it is installed locally to minimize latency. However, this is the most expensive type of WAF and necessitates storing and maintaining physical equipment.
- **Host-based WAF: C**an be fully integrated into the software of an application. This option is cheaper than network-based WAFs and is more customizable, but it consumes extensive local server resources, is complex to implement, and can be expensive to maintain. The machine used to run a host-based WAF often needs to be hardened and customized, which can take time and be costly.
- **Cloud-based WAF: A**n affordable, easily implemented solution, which typically does not require an upfront investment, with users paying a monthly or annual security-as-a-service subscription. A cloud-based WAF can be regularly updated at no extra cost, and without any effort on the part of the user. However, since you rely on a third party to manage your WAF, it is important to ensure cloud-based WAFs have sufficient customization options to match your organization’s business rules.

# SOC (Security Operations Center)

![Untitled](/assets/img/pitcures/red-team/security-devices4.png)

In a data center or large enterprise environment, a SOC is necessary for network security. The SOC is often a physical room within the organization’s office where several employees continually monitor network traffic, alerts, and visualized information that could be used to respond to a potential cyber-incident. The SOC focuses on security of the network rather than network performance and utilization

SOC and SOC engineers perform a few standard functions:

- 24/7 continual monitoring across the entire environment
- Preventative maintenance and deployment of cybersecurity appliances
- Alert ranking to determine priority during incident response
- Threat response when a cyber-threat is found
- Containment and eradication of discovered threats
- Root-cause analysis after a cyber-incident
- Assessment and management of compliance for various regulations

SOCs will incorporate alerts from various components of the organization:

- endpoints
- network equipment
- firewalls
- servers (internal or web)
- cloud resources
- virtual devices
- mobile devices
- applications

## **What Is A SIEM (Security Information And Event Manager)?**

A Security Information and Event Management (SEIM) tool:

- aggregates logs data from various systems
- stores the information in an organized fashion
- correlates linked events
- applies data analytics and machine learning to detect trends
- detects devices and software
- centralizes configuration and security management
- classifies threats for efficient triage

## SOC and SIEM: what are the differences?

SOC stands for Security Operation Center. A SOC focuses on threat monitoring and incident qualification.

To achieve this, analysts use a tool called a “SIEM”, for Security Information Management System. A SIEM integrates software used to monitor corporate infrastructures. Analysts configure a set of correlation rules according to the recommended security policy to detect possible threats.

## EDR: Endpoint Detection Response

EDR software monitors terminals (computers, tablets, mobile phones, etc.), not the system network.

To do this, EDR software analyze the uses made of the monitored terminals, in particular through behavioral analysis. This enables the recognition of behaviors that deviate from a norm after a learning phase. EDR software are also capable of monitoring the exploitation of security flaws.

The advantage of EDR solutions is that they allow companies to protect itself against both known (e.g., a virus) and unknown attacks by analyzing suspicious behaviors.

## NDR: Network Detection and Response

NDR software provide extended visibility to SOC teams across the network to detect the behavior of potentially hidden attackers targeting physical, virtual, and cloud infrastructures. It complements the EDR and SIEM tools.

The NDR approach provides an overview and focuses on the interactions between the different nodes of the network. Obtaining a broader detection context can indeed reveal the full extent of an attack and enable faster and more targeted response actions.

## XDR: Extended Detection and Response

XDR software help security teams solve threat visibility problems by centralizing, standardizing, and correlating security data from multiple sources. This approach increases detection capabilities compared to specific terminal detection and response tools (EDR).

For example, XDR provides complete visibility by using network data to monitor vulnerable (unmanaged) endpoints that cannot be seen by EDR tools.

XDR analyzes data from multiple sources (emails, endpoints, servers, networks, cloud streams...) to validate alerts, reducing false positives and the overall volume of alerts. This correlation of indicators from multiple sources allows XDR to improve the efficiency of security teams.

In summary:

- **EDR: provides more detail but less network coverage.**
- **NDR: covers the network but does not monitor endpoints.**
- **XDR: breaks down the boundaries of detection perimeters, brings automation to accelerate investigations and detect sophisticated attacks.**

## MDR: Managed Detection Response

The acronym MDR stands for managed detection and response. These solutions are managed by a cybersecurity provider. They are operated by an internal or outsourced SOC and enable end-to-end addressing of cyber threats.

An analyst can perform remediation when a threat is detected and confirmed through automation, including the use of an orchestration tool (SOAR for Security Orchestration Automation and Response). Depending on an entity's cybersecurity maturity level, it is also entirely possible to automatically apply remediation.

These solutions allow an acceleration of the processing of alerts.

# Sources:

- [https://www.garlandtechnology.com/blog/ids-vs-ips-go-to-tools-for-modern-security-stacks](https://www.garlandtechnology.com/blog/ids-vs-ips-go-to-tools-for-modern-security-stacks)
- [https://www.geeksforgeeks.org/](https://www.geeksforgeeks.org/)
- [https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/](https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/)
- [https://www.imperva.com/learn/application-security/what-is-web-application-firewall-waf/](https://www.imperva.com/learn/application-security/what-is-web-application-firewall-waf/)