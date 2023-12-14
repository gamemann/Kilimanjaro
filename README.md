# Kilimanjaro
This is a packet processing/forwarding program I made for a gaming community I used to be a part of that utilized its own [Anycast network](https://www.cloudflare.com/learning/cdn/glossary/anycast-network/). This gaming community hosted game servers under this network in games such as Team Fortress 2, Garry's Mod, and Counter-Strike.

This program should be deployed on edge servers meant to forward traffic/announce IP blocks via BGP. It utilizes [XDP](https://www.iovisor.org/technology/xdp) and the [IPIP](https://en.wikipedia.org/wiki/IP_in_IP) network protocol.

**Note** - This code was last updated on **June 5th, 2022**. There were changes made to this software after this date in a private repository, but I only wanted to open-source the code **I wrote**. I also removed additional code that wasn't mine.

This program contains a lot of code others will likely find useful with XDP, AF_XDP, and more.

## No Longer Supported!!!
This project is no longer supported and honestly unfinished/outdated. I no longer have the time to work on this project and I'm also tied to NDAs that restrain me from sharing layer-7 filtering code which is what would have made this stateful firewall most effective. I still believe a lot of the code is useful if you're aiming to build a stateful firewall with special features such as `A2S_INFO` caching with XDP, but getting these applications running in production requires tuning from developers who understand the inner-workings of Kilimanjaro in my opinion plus the other smaller tools I've made such as my TC IPIP Mapper [tool](https://github.com/gamemann/TC-IPIP-Mapper). With that said, I did have this running in production a couple of years ago with some small issues in a gaming community in the past (overall, it worked fairly well with what we had at the time, but I had a very specialized setup).

As for the biggest issues with this project, I believe Killfrenzy was the most flawed since I shouldn't have used Django and implemented back-end communication from the web back-bone to Killtrocity inside of Django itself using background tasks. This resulted in a lot of threading/performance issues. Additionally, the low-level socket I made [here](https://github.com/gamemann/Kilimanjaro/blob/master/src/socket.c#L135) within Kilimanjaro that interacts with Killtrocity would sometimes break after a week or so until you restarted Kilimanjaro. Out of all the programs, I do believe Kilimanjaro is the most complete.

## Useful Programs
* [Killtrocity](https://github.com/gamemann/Killtrocity) - Used for communication between Kilimajaro and Killfrenzy.
* [Killfrenzy](https://github.com/gamemann/Killfrenzy) - Web back-end used to modify IPs, display/consume stats, and more.

Additionally, I wrote an [IP mapper tool](https://github.com/gamemann/TC-IPIP-Mapper) that deploys on the dedicated servers running game servers so that traffic from the game server goes through the same edge server the client's traffic came in via IPIP. This allows for server-side validation for layer-7 filters if implemented.

## Features
* Utilizes [XDP](https://www.iovisor.org/technology/xdp) and [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html) for fast packet processing.
* Automatically whitelists outbound traffic via port punching and reports to Killfrenzy to sync all edge servers.
* Collects a lot of stats such as packets/bytes per second and sends them to Killfrenzy.
* Performs [A2S_INFO](https://developer.valvesoftware.com/wiki/Server_queries#A2S_INFO) caching through [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html) with challenge support.
* Rate limits for TCP, UDP, and ICMP.
* Whitelist and blacklist maps with CIDR support that allows you to allow/drop traffic with IP ranges.

**Note** - I didn't include any of the layer-7 filters that were implemented in the private version of this project. You may implement client/server-side layer-7 filters in the `src/xdp_prog.c` file. It works very well with the project's port punching functionality that allows outbound connections through automatically.

## Credits
* [Christian Deacon](https://github.com/gamemann)
