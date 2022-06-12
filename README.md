# tcpanatomy
Low-level lightweight network monitoring tool.

TCPANATOMY is a low-level lightweight standalone tool allowing you to monitor and collect data about your network. Built with simplicity in mind. 
It does not require any third-party libraries like `pcap`. 

It is not a replacement of tcpdump but rather a tool meant to be used in situations where all you need is a quick look over the data flying through your network.

I decided to build the tool to get a bit more intimate with the TCP/IP stack and processing raw network data. 

```
TCPANATOMY - Low-level lightweight network monitoring tool.
Written and maintained by Yordan Stoychev (anatomicys@gmail.com)
Options:
	-v4 - displaying IPv4 packets
	-v6 - displaying IPv6 packets
	-p - displaying the physical route of the frames
	-A - IPv4, IPv6 and physical route all displayed
	--addr - limit to a certain address (source or destination)
	--src - limit to a certain source address
	--dest - limit to a certain destination address
To be implemented: 
	--port - limit to a certain port (source or destination)
	--srcPort - limit to a certain source port
	--destPort - limit to a certain destination port
    --type - limit to a certain type of packets

```

![IPv4 with physical enabled](https://imgur.com/lfz0fhe)

![IPv4 with --addr filtering](https://imgur.com/34JZCXC)

## Building
Refer to the `build.sh` file.