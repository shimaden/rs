# rs
Estimate router global address

# Description
Rs estimates the global unicast address of the router that first sent a Router Advertisement on the link-local network. Once rs receives a Router Advertisement whose source address is a link-local unicast address, the program calculate the global unicast address by the EUI-64 algorithm. Although rs itself begins to send a Router Solicitation constantly right after the execution, only the Router Advertisement first received is used whether it was triggered by a Router Solicitation from the program or not.

# Synopsis
rs &lt;interface>
  
