# Logging for disaster
Practical steps to help be ready to investigate a compromise. A presentation delivered to the [College IT Conference 2025](https://citc.college/).

**As a presentation on YouTube:** Coming soon!

By **James Preston** of [ANSecurity](https://www.ansecurity.com/).

Personal blog at [myworldofit.net](https://myworldofit.net/).

<details>
<summary>By the end of this presentation you will</summary>

</details>
<details>
<summary>What are others saying?</summary>

</details>

<details>
<summary>Why do I need to log?</summary>

# Why do I need to log?

To answer questions, such as:

* Sophos detected a malicious program on a computer - where did it come from?
* Based on the data in a threat intel report have we been impacted?
* What files have been copied to the Internet from a computer?

</details>

<details>
<summary>What should I log?</summary>

</details>

<details>
<summary>How do I capture logs?</summary>

</details>

<details>
<summary>Where should those logs go?</summary>

# Where should those logs go?

* Local storage
* Centralised storage
* Consider 'cloud' options

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
<summary>Demo 1 – the utility of keeping logs</summary>

</details>
<details>
<summary>I’m sold! What do I need to do?</summary>

</details>

<details>
<summary>Demo 2 – Logs from multiple sources</summary>

</details>

<details>
<summary>When you get back to your institutions</summary>

</details>
