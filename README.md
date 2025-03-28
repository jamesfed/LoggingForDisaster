# Logging for disaster
Practical steps to help be ready to investigate a compromise. A presentation delivered to the [College IT Conference 2025](https://citc.college/).

Following on from:
* [Practical steps to help mitigate the risk of Zero-Day vulnerabilities.](https://myworldofit.net/?p=11366)
* [All of this has happened before. All of this will happen again (MITRE ATT&CK).](https://myworldofit.net/?p=11325)

**As a presentation on YouTube:** Coming soon!

By **James Preston** of [ANSecurity](https://www.ansecurity.com/).

Personal blog at [myworldofit.net](https://myworldofit.net/).

# By the end of this presentation you will
* Have direction on the creation of a logging policy.
* Understand the utility of logging in the context of incident response.
* Be able to identify useful log sources.
* Have options on how to obtain and store your logs.
* Be ready to log!

# My intent
* Provide a 'quick start' point in a direction for effective logging.

# What are others saying?

## Center for Internet Security
* [https://www.cisecurity.org/](https://www.cisecurity.org/)
* [https://cas.docs.cisecurity.org/en/latest/source/Controls8/](https://cas.docs.cisecurity.org/en/latest/source/Controls8/)
* [https://www.cisecurity.org/insights/white-papers/audit-log-management-policy-template-for-cis-control-8](https://www.cisecurity.org/insights/white-papers/audit-log-management-policy-template-for-cis-control-8)

## National Cyber Security Centre (NCSC)
* [https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring](https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring)

## Log configuration guidance
* [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
* [https://www.cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks)

### Apache web server
From the CIS Benchmarks
![CIS Benchmarks](https://github.com/user-attachments/assets/ced08f6b-13c3-4373-89e2-e475d200e82d)

### VMware ESXi
From the CIS Benchmarks
![CIS Benchmarks](https://github.com/user-attachments/assets/b170440d-b942-4aa7-9c0f-16861df33302)

# Why do I need to log?
To answer questions, such as:
* Sophos detected a malicious program on a computer - where did it come from?
* Based on the data in a threat intel report have we been impacted?
* What files have been copied to the Internet from a computer?

But also...
* To identify the root cause of an incident (non-security related!).
* To comply with regulations.
* Generally a 'good idea'.

Perhaps most of all so that you don't have to use sentences like:
* "fined for a breach that put personal information of 79,404 people at risk"
* "The unidentified hackers"
* "The security measures of Advanced's subsidiary fell seriously short of what we would expect from an organisation processing such a large volume of sensitive information," Mr Edwards said.
* "There is no excuse for leaving any part of your system vulnerable," Mr Edwards added.

From: [BBC News - NHS software provider fined £3m over data breach after ransomware attack](https://www.bbc.co.uk/news/articles/cp3yv1zxn94o)

## Beware - rabbit hole ahead!
* Deception and honeypots.
* Log review.

# Demo 1 – data exfiltration

[Validato](https://validato.io/), manual exfiltration, and [Microsoft Defender EDR](https://www.microsoft.com/en-gb/security/business/endpoint-security/microsoft-defender-endpoint)

## Scenario setup
![Scenario setup 1](https://github.com/user-attachments/assets/011876f3-e0ec-4834-ab05-2f08a98ebd5e)

![Scenario setup 2](https://github.com/user-attachments/assets/25f0a188-1307-4d05-b2ad-b438dbd6a19d)

## Defenders point of view
![Data exfiltration-1](https://github.com/user-attachments/assets/e9e8f68f-c1ab-4b75-9c70-2fde80051620)

![Data exfiltration-2](https://github.com/user-attachments/assets/d6d0694d-e7f3-4adc-8521-2078346653c2)

![Data exfiltration-3](https://github.com/user-attachments/assets/c688dc20-a69b-411a-b7ac-3515d274aabf)

# What should I log?

## Data that'll be useful in forensic analysis
* New application process.
* DNS requests.
* URL requests.
* New/modified file and registry keys.
* Loading of drivers.
* Reading specific file types (e.g. .docx/.pdf/.xlsx).
* Script/command line interface use.

## Data that'll be useful in threat hunting
* [https://github.com/sophoslabs/IoCs](https://github.com/sophoslabs/IoCs).
* [https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information).
* [https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports](https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports).
* URLs.
* File hashes (MD5/SHA1/SHA256).
* File names and paths.
* IP addresses.
* Domains.

## Abnormal events
* AppLocker blocked the execution of a new application.
* Excessive requests to unauthorised web or file sharing services.
* Break glass account used... careful about to hit that rabbit hole.

## Sigma rules as inspiration
* [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

## Log retention
* Minimum 90 days for all logs.
* Target as long as you can (365 days wouldn't be abnormal) for high value logs.

# How do I capture logs?

## Windows
* Deploy [sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) everywhere.
* Increase the minimum local retention for Event Logs.
  * ~2GB limit for 'live'.
* [NXLog CE](https://nxlog.co/products/nxlog-community-edition) and [Winlogbeat](https://www.elastic.co/guide/en/beats/winlogbeat/8.17/winlogbeat-installation-configuration.html).
  * Direct out of Event Logs.
  * Read file system.

## Linux
* rsyslog.
  * imklog.
  * imjournal.
  * Read file system (e.g. for Apache).

## Network appliances/Infrastructure
* Syslog.
  * Common Event Format (CEF).
    * [FortiGate](https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/604144/cef-support).
    * [Palo Alto Networks](https://github.com/jamesfed/PANOSSyslogCEF).
    * [SonicWall](https://www.sonicwall.com/support/knowledge-base/how-to-configure-sonicos-syslog-settings-for-microsoft-sentinel-integration/241003073427260).

## Cloud Services
* API connectors.
  * Normally some kind of agent required that connects into the cloud service and downloads logs on a routine.
  * [Sophos SIEM integration script](https://github.com/sophos/Sophos-Central-SIEM-Integration).

From [LimaCharlie](https://limacharlie.io/).
![LimaCharlie](https://github.com/user-attachments/assets/e0c52226-cb01-4b55-be08-e0ead4f487dc)

# Where should those logs go?
* Local storage.
* Centralised storage.
  * [https://graylog.org/](https://graylog.org/).
  * Lots of options out there based on [Elasticsearch](https://www.elastic.co/enterprise-search) or [OpenSearch](https://opensearch.org/).
* Consider 'cloud' options.
  * Perhaps just as a relay for end-user devices working remotely.
* In an emergency and you don't have anything setup:
  * [https://docs.velociraptor.app/](https://docs.velociraptor.app/)

## Consider: authentication and encryption
* Network appliances don't always support both/either.
* May need to use some form of logging 'proxy'.
* If running a 'cloud' logging service the importance is even greater.
* Don't underestimate a threat actors resourcefulness, easy to generate sufficient logs to overwhelm a system or inject malicious content into logs.

## If storing on-premises consider
* Network level access controls to the log system.
* Authentication to the log system.
* Dependencies on systems that may be offline in an incident (compute, storage, networking, authentication).

## A recommendation for on-premises
* Place the server(s) in a dedicated 'logging' network.
* Restrict access into that network with a network firewall, broadly allow connections to the ports that logging agents talk to, restrict by source network/IP/user/device access to the management interface.
* Dedicated physical server or servers (3 smaller nodes in a cluster is better than a single node by itself).
* Strong authentication (phishing resistant) as the 'day to day' access, with a fallback to local authentication with a strong (long) passphrase.

# Volume vs value (examples)
* Firewall traffic logs - VERY high volume, low relative value.
* DNS logs - high volume, low-medium relative value.
  * But.... DNS is encrypted now.
* Command line logs - low-medium volume, high relative value.
* Previously unseen application launched (or attempted to) - low volume, high relative value.

# Sharing your logs
* Volume (TBs of logs!) is often the main problem.
* Bulk file transfer of text files.
* Not uncommon to grant read-only access to the centralised log store.
* Export from >X<Search to JSON.
* Export with backup feature and then import.
  * [OpenSearch snapshots](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/index/).

# Demo 2 – Malware detection triggers investigation

[Validato](https://validato.io/), [Microsoft Defender](https://www.microsoft.com/en-gb/security/business/endpoint-security/microsoft-defender-endpoint), [LimaCharlie EDR](https://limacharlie.io/)

## Detection by Microsoft Defender

![Defender awakes!](https://github.com/user-attachments/assets/94c0b806-f8c4-44e1-a459-5160b5e5e520)

## Defenders point of view

![EDR-1](https://github.com/user-attachments/assets/b50da0d5-61b5-41ba-b26a-756d97d79a0f)

![EDR-2](https://github.com/user-attachments/assets/de3dc61b-7e56-40f6-a8df-43188afc6804)

![EDR-3](https://github.com/user-attachments/assets/fb4507aa-a751-4c13-91b2-199fa764280b)

![EDR-4](https://github.com/user-attachments/assets/a6d3d67b-f0c3-4494-8528-16906986a8c9)

![EDR-5](https://github.com/user-attachments/assets/d9edfc2a-71a8-448b-83b5-6ca4cc7a2485)

![EDR-6](https://github.com/user-attachments/assets/1ddf7fcd-87cb-4442-868d-433363bf46bf)

# Demo 3 – Web shell party mode 🎉🥳

[VirusTotal](https://www.virustotal.com/), [wordpress_shell.php](https://github.com/BlackArch/webshells/blob/master/php/wordpress_shell.php), [LimaCharlie EDR](https://limacharlie.io/).

## Web shell detected!
![WordPress webshell](https://github.com/user-attachments/assets/25948df7-6f00-4da6-a183-364a9ef1dc64)

## Threat actors point of view
![ifconfig](https://github.com/user-attachments/assets/9c28b361-6b57-4433-8d95-54f2f9623c6e)

![Or coninminer](https://github.com/user-attachments/assets/1c29f7ef-cac9-4bbb-bf6f-92792ab75efb)

## Defenders point of view
![INVESTIGATE!](https://github.com/user-attachments/assets/25b63902-b125-4707-befb-fa300d4e3e18)

![INVESTIGATE!!](https://github.com/user-attachments/assets/f4d496c2-ebe3-4a71-9722-9d2be86bf503)

![INVESTIGATE!!!](https://github.com/user-attachments/assets/b1623e7e-2fd4-47cb-8060-3297d41a84a4)

# Some other cool things you can do with logs

![Nessus](https://github.com/user-attachments/assets/b7553139-3f9b-4bbe-aa8d-471bb62b43cb)

![Be amazed by the Christmas spike in brute force attacks](https://github.com/user-attachments/assets/9c71622f-a74f-46dd-983a-51305736c45b)

![Get longer data retention than cloud services provide](https://github.com/user-attachments/assets/a8b9f857-1ef9-4c7a-8be0-faf1535591c9)

# When you get back to your institutions

* Talk with senior leadership about establishing a formal policy for logging.
  * Then take that policy and turn it into practice/procedure.
* Find 1 (or 3!) old(er) servers (desktops), fill them with disks (8TB SSDs are cheap), configure a logging stack of your choice.
  * Get firewall, web server, AV agent, and authentication logs flowing into them.
* Review options for an EDR service.
  * [LimaCharlie](https://limacharlie.io/) really is a great entry point, try it out on some web servers and go snooping!

## But also don't forget to:

* Do maintenance! Don't let that logging system run out of disk space!
* Check all log sources are sending logs.
* Routine check that the times of systems are in sync.

## If you have the spare time:

* Conduct audit log reviews.
  * Perform some 'malicious' activities and then check that the logs you expect were captured.
    * [There is software that can help with this](https://validato.io/).
  * Use threat intel reports.

# Logging and being able to respond is great...

But a good defence is still a good defence.

* Build a culture of reporting abnormal events.
* Install AV everywhere, including on Linux web servers!
* MFA (or even better strong authentication) everything!
* Decrypt!
  * Inbound (where you own the private key already).
  * Outbound (where you generate new trusted certificates on the fly for services that you don't have the private key for).
* Configure outbound filtering!
  * Block access to remote access tools (legitimate and otherwise).
  * Strict outbound filtering from services that allow connections from untrusted networks/devices.
* Test your backups!

![ANSecurity](https://github.com/user-attachments/assets/5f27bfb0-2925-4748-94b7-23aa224eab26)

![WAF](https://github.com/user-attachments/assets/a9aab5f4-f072-4472-b211-5426782bd9c3)

# jpreston@ansecurity.com
