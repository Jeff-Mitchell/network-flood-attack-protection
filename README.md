# CSC 7078 Secure Softwarized Networks
## The Detection And Protection Again TCP PSH Floods
## Jeff Mitchell 40203212

#### Overview

This is a python sdn application intended to be run through sdn-cockpit. The python application uses the ryu manager to detect and protect a victim from a TCP and specifically a PSH flood attack. The topology of the virtual net consists of 3 hosts all connected to a switch. The hosts are:

1. A1 - This is our attacker and has the IP `11.0.0.1`
1. N1 - This is our normal traffic user and has `IP 11.0.0.2`
1. V1 - This is our victim and has `IP 22.0.0.1`

The setup of this project is to launch an attack from a1 to v1 and have the python application running on the controller / switch detect the PSH flood atttack and respond accordinly while having minimal disturbances to other users on the network. the application works by using parts of learning switch to automatically allow traffic to flow in the network to begin with. The applications the works by extracted different pieces of data from the packets flowing through the network. from the python file we can see that the ethernet, ip and tcp protocols are extracted to get information such as source and destination addresses (both MAC and IP) and In ports and Out ports to correctly forward traffic automattically.

#### How The Code Works

A total count of all packets is used to calculate a instant network load to help with analysis. All of the above allows our controller to work naturally with all hosts on the network seamlessly. Now we can begin to narrow down the paacket type that we are going to look at. Using the previously extracted TCP data fromeach packet we can further refine to look for packets that meet the specific TCP_PSH flag we are looking for.

The controller also keeps a running dictionary of all the ip addresses which have sent PSH packets through the network and includes a PSH packet count on a per MAC address basis. This is done using the following

```python
tcp_psh_packets_by_ip = dict()
```

The python file contains a function called `detect_tcp_psh_packets()` which is called from the `packet_in handler` on every packet received but only executes when the `packet_in` is a TCP type packet which has the `TCP_PSH` flag set. This results in the function returning true and increaseing the PSH packet count for the specific MAC address provided by arguments passed through the function.

This function is where all of the PSH packet analysis occurs. An attacker who floods the controller with PSH packets will quickly hit the limit set by the function. After some expirementing the limit has been set to around 2500 PSH packets and then the attacker will be issued a warning to stop flooding the network followed by a 60 second traffic ban through the use of a flow rule which will drop all packets with a 60 second `hard_timeout` and `idle_timeout`.

If this was not attack and just heavy traffic flow for another reason they will be allowed to start sending traffic again after 60 seconds and should make sure to limit their traffic flow as to not trigger the flood protection again.

If this was a real attack and the PSH flood starts again after the first temporary warning and ban. The attacker is given up to a total of 3 three temporary warnings and bans before a permenant block rule is place on the attackers MAC address, indefinetely blocking all traffic from this source untill further review.

The temporary bans and warning are put in place by calling the `launch_temp_countermeasures()` function and passing in the attackers MAC address as an argument. this function contains the messages that are printed to screen and tracks the total number of warnings on each MAC address useing a dictionary in a similiar way to how to total count of tcp PSH packets is traked. The permenant warning and ban is contained within another function call `launch_perma_countermneasures()` with a similar warning message and warning tracking system as the temporary counter measures but with the addition of the permenant block rule which has a higher priorty and its hard_timeout and idle_timeout set to zero which means that the rule will never timeout with the application is running.


## Generating the traffic

The attack traffic and the normal traffic will be generated using the xnodes within mininet and using the hpin3 command.

### normal traffic

The traffic which will be sent from the normal user n1 to the victim v1 is generated as follows

```
hping3 22.0.0.1 -p 80 -d 120
```

- `22.0.0.1` being the ipv4 address of where the traffic is being sent
- `-p 80` this tells hping3 to send the traffic specifically through port 80, this is not required but is representative of real TCP traffic
- `-d 120` this tell hping3 to set the size of the data field of the packet to 120 units as the default is 0

There is no need to specify to hping3 that we are using the TCP protocol as that is the default mode of hping3 anyway

### flood traffic

The traffic which will be sent from the attacker a1 to the victim v1 is generated as follows

```
hping3 22.0.0.1 -p 80 -P --flood
```

- `22.0.0.1` being the ipv4 address of where the traffic is being sent
- `-p 80` this tells hping3 to send the traffic specifically through port 80, this is not required but is representative of real TCP traffic
- `-P` this tells hping3 to send TCP packets with the PSH flag bits as this is the type of attack we are trying to detect
- `--flood` this tells hping3 to send off the packets ass quickly as possible

There is no need to specify to hping3 that we are using the TCP protocol as that is the default mode of hping3 anyway






