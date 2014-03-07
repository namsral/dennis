Dennis the DNS Menace
===

*Tailored DNS responses*

Dennis is a DNS server which can serve customised DNS responses on a per user basis.

On its own Dennis isn't very useful but by adding a DNS recursor and a HTTP(S) proxy, Dennis can bypass geo-blocking for thousands of users.

How it works
---

Users are identified by their IP address, and each user can setup an unlimited number of custom DNS responses.


Setup
---

Requirements:

- Redis instance
- DNS recursor like PowerDNS *(for test purposes you can use your ISPs or Google's DNS server)*
- HTTP proxy like Nginx *(To proxy HTTPS, you'll require support for rfc3546)*

**Build, configure and run Dennis.**

0. Build Dennis, make sure you install the dependancies first:

		$ go build dennis.go

0. Run Denis with a config file:

		$ cat > dennis.conf
		[main]
		    bind-addr = 127.0.0.1:8054
		    redis-addr = 127.0.0.1:6379
		    dnsfwd-addr = 127.0.0.1:8053
		    portal-addr = 127.0.0.1
		    logfile = /tmp/dennis.log

		$ ./dennis -config dennis.conf
			Running on 127.0.0.1:8054
	
	`bind-addr`: bind Dennis to this address  
	`redis-addr`: address of the Redis instance  
	`dnsfwd-addr`: DNS server address for forwarding requests  
	`portal-addr`: this is the address unregistered users will get, works like a WiFi Portal  

0. Create a test user identified by IP `127.0.0.1` and load it into Redis:
	
	    $ cat > data.txt
	        SET gateway:90d1ed58-399e-5ce9-93d8-28f0c86c80e0 53e48371-0bda-4f45-8d03-b0943c89c4ea
	        SET user:53e48371-0bda-4f45-8d03-b0943c89c4ea:domain:example.com. 1.0.0.1
	        SET user:53e48371-0bda-4f45-8d03-b0943c89c4ea:domain:example.org. 1.0.0.2

	    $ cat data |redis-cli --pipe
	
	Format `gateway:<uuid5.NAMESPACE_OID:ip> <str:user_id>`  
	Format `user:<str:user_id>:domain:<root_domain> <ip>`  
	`192.168.10.2` is the IP address of your HTTP proxy 1  
	`192.168.10.3` is the IP address of your HTTP proxy 2  


0. Test the setup and fire off some DNS queries with Dig:

    	$ dig @127.0.0.1 -p 8054 example.com
        	...
        	example.org.    0   IN  A   1.0.0.1

    	$ dig @127.0.0.1 -p 8054 foo.example.org
        	...
        	foo.example.org.    0   IN  A   1.0.0.2

Configuring Redis, Nginx and PowerDNS Recursor is out of scope for this document.


Security
---

Don't run Dennis on a privileged port, use firewall rules instead to make Dennis available on TCP & UDP port 53:

Redirect TCP/UDP traffic from external:53 to internal:8054 

	$ iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 53 -j REDIRECT --to-port 8054
	$ iptables -A PREROUTING -t nat -i eth0 -p udp --dport 53 -j REDIRECT --to-port 8054


Query Process
---

![Logic](https://raw.github.com/namsral/dennis/master/dennis_query_process.png)

License
---

Dennis is licensed under the terms of the MIT license, see attached LICENSE file for more details.