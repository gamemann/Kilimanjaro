# Kilimanjaro
This is a packet processing/forwarding program I made for a gaming community I used to be a part of that utilized its own [Anycast network](https://www.cloudflare.com/learning/cdn/glossary/anycast-network/). This gaming community hosted game servers under this network in games such as Team Fortress 2, Garry's Mod, and Counter-Strike.

This program should be deployed on edge servers meant to forward traffic/announce IP blocks via BGP. It utilizes [XDP](https://www.iovisor.org/technology/xdp) and the [IPIP](https://en.wikipedia.org/wiki/IP_in_IP) network protocol.

**Note** - This code was last updated on **June 5th, 2022** and I no longer work on this project. There were changes made to this software after this date in a private repository, but I only wanted to open-source the code **I wrote**.

## Additional Programs
* Killtrocity - Used for communication between Kilimajaro and Killfrenzy.
* Killfrenzy - Web back-end used to modify IPs, display/consume stats, and more.

Additionally, I wrote an IP mapper tool that deploys on the dedicated servers running game servers so that traffic from the game server goes through the same edge server the client's traffic came in via IPIP.

## Features
* Utilizes [XDP](https://www.iovisor.org/technology/xdp) and [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html) for fast packet processing.
* Automatically whitelists outbound traffic and reports to Killfrenzy to sync all edge servers.
* Collects a lot of stats such as packets/bytes per second and sends them to Killfrenzy.
* Performs [A2S_INFO](https://developer.valvesoftware.com/wiki/Server_queries#A2S_INFO) cache through [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html) with challenge support.


## Credits
* [Christian Deacon](https://github.com/gamemann)