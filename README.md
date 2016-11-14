Refer to `ryu/ryu/app/routingPkt.py` and `ryu/ryu/app/igmpRouting.py` for the routing scripts.

To start the ryu controller with the above application use from the ryu directory:

```bash
ryu-manager video_multicast_app/igmpRouting.py --observe-links
```

TODO: Need to integrate the l3 code with the above apps.

We are using Openflow v1.3 so need to configure the switches accordingly. For example:
sudo ovs-vsctl set bridge s1 protocols=OpenFlow13
You can use `./scripts/setup_switches.sh <no_of_switches>` to do this for you.
(Might need to do a `chmod +x scripts/setup_switches.sh` first.)

To run the multicast server client code, need to install a route on each host (For now do it manually, need to make it a part of the script):
`route add -net 224.0.0.0 netmask 224.0.0.0 eth0`

