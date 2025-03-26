# Logging for disaster
Practical steps to help be ready to investigate a compromise. A presentation delivered to the [College IT Conference 2025](https://citc.college/).

**As a presentation on YouTube:** Coming soon!

By **James Preston** of [ANSecurity](https://www.ansecurity.com/).

Personal blog at [myworldofit.net](https://myworldofit.net/).

<details>
<summary>By the end of this presentation you will</summary>

# By the end of this presentation you will
* Have direction on the creation of a logging policy.
* Understand the utility of logging in the context of incident response.
* Be able to identify essential, desirable, and optional log sources.
* Have options on how to obtain and store your logs.
* Be ready to log!

</details>

<details>
<summary>What are others saying?</summary>

# What are others saying?

## Center for Internet Security
* [https://www.cisecurity.org/](https://www.cisecurity.org/)
* [https://cas.docs.cisecurity.org/en/latest/source/Controls8/](https://cas.docs.cisecurity.org/en/latest/source/Controls8/)
* [https://www.cisecurity.org/insights/white-papers/audit-log-management-policy-template-for-cis-control-8](https://www.cisecurity.org/insights/white-papers/audit-log-management-policy-template-for-cis-control-8)

## National Cyber Security Centre (NCSC)
* [https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring](https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring)

## Vendor documentation
* [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)

</details>

<details>
<summary>Why do I need to log?</summary>

# Why do I need to log?
To answer questions, such as:
* Sophos detected a malicious program on a computer - where did it come from?
* Based on the data in a threat intel report have we been impacted?
* What files have been copied to the Internet from a computer?

But also...
* To identify the root cause of an incident (non-security related!).
* To comply with regulations.
* Generally a 'good idea'.

## Beware - rabbit hole ahead!
* Deception and honeypots.
* Log review.

</details>

<details>
<summary>Demo 1 – data exfiltration</summary>

# Demo 1 – data exfiltration

[Validato](https://validato.io/), manual exfiltration, and [Microsoft Defender EDR](https://www.microsoft.com/en-gb/security/business/endpoint-security/microsoft-defender-endpoint)

## Scenario setup
![Scenario setup 1](https://github.com/user-attachments/assets/011876f3-e0ec-4834-ab05-2f08a98ebd5e)

![Scenario setup 2](https://github.com/user-attachments/assets/25f0a188-1307-4d05-b2ad-b438dbd6a19d)

## Defenders point of view
![Data exfiltration-1](https://github.com/user-attachments/assets/e9e8f68f-c1ab-4b75-9c70-2fde80051620)

![Data exfiltration-2](https://github.com/user-attachments/assets/d6d0694d-e7f3-4adc-8521-2078346653c2)

![Data exfiltration-3](https://github.com/user-attachments/assets/c688dc20-a69b-411a-b7ac-3515d274aabf)

</details>

<details>
<summary>What should I log?</summary>

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
* [https://github.com/sophoslabs/IoCs](https://github.com/sophoslabs/IoCs)
* [https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information)
* [https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports](https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports)

* URLs.
* File hashes (MD5/SHA1/SHA256).
* File names and paths.
* IP addresses.
* Domains.

## Abnormal events
* AppLocker blocked the execution of a new application.
* Excessive requests to unauthorised web or file sharing services.
* Break glass account used... careful about to hit that rabbit hole.

</details>

<details>
<summary>How do I capture logs?</summary>

# How do I capture logs?

## Windows
* From Windows Event Logs, [NXLog CE](https://nxlog.co/products/nxlog-community-edition), 

## Linux


## Network appliances


## Cloud Services
* API connectors.
* 

</details>

<details>
<summary>Where should those logs go?</summary>

# Where should those logs go?
* Local storage
* Centralised storage
* Consider 'cloud' options

## Consider: authentication and encryption
* Network appliances don't always support both/either.
* May need to use some form of logging 'proxy'.
* If running a 'cloud' logging service the importance is even greater.
* Don't underestimate a threat actors resourcefulness, easy to generate sufficient logs to overwhelm a system.

## If storing on-premises consider
* Network level access controls to the log system.
* Authentication to the log system.
* Dependencies on systems that may be offline in an incident (compute, storage, networking, authentication).

## A recommendation for on-premises
* Place the server(s) in a dedicated 'logging' network.
* Restrict access into that network with a network firewall, broadly allow connections to the ports that logging agents talk to, restrict by source network/IP/user/device access to the management interface.
* Dedicated physical server or servers (3 smaller nodes in a cluster is better than 1 single node by itself).
* Strong authentication (phishing resistant) as the 'day to day' access, with a fallback to local authentication with a strong (long) passphrase.

# Volume vs value
* Firewall traffic logs - VERY high volume, low relative value
* DNS logs - high volume, low-medium relative value
  * But.... DNS is encrypted now
* 

</details>

<details>
<summary>I’m sold! What do I need to do?</summary>

# I’m sold! What do I need to do?

## But also don't forget to:

* Do maintenance! Don't let that logging system run out of disk space!
* Check all log sources are sending logs.
* Routine check that the times of systems are in sync.

## If you have the spare time:

* Conduct audit log reviews.
  * Perform some 'malicious' activities and then check that the logs you expect were captured.
    * [There is software that can help with this](https://validato.io/).
  * Use threat intel reports 

</details>

<details>
<summary>Demo 2 – Malware detection triggers investigation</summary>

# Demo 2 – Malware detection triggers investigation

</details>

<details>
<summary>Demo 3 – Web shell party mode 🎉🥳</summary>

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

</details>

<details>
<summary>When you get back to your institutions</summary>

# When you get back to your institutions

</details>

<details>
<summary>Logging and being able to respond is great...</summary>

# Logging and being able to respond is great...

But a good defence is still a good defence.

* Decrypt!
* Outbound filtering!
* MFA (or even better strong authentication) everything!
* 

</details>
