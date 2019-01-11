EXEC = rs
OBJS = rs.o setup_socket.o iface.o nd_router.o checksum.o eui64.o \
		compose_ip6_hdr.o compose_icmp6_hdr.o
TEST_EXEC = nd_router iface

all: $(EXEC)

rs: $(OBJS)
	g++ -std=c++11 -o $(EXEC) $(OBJS) -pthread

.cpp.o:
	g++ -Wall -g -O2 -c $<

.c.o:
	gcc -Wall -g -O2 -c $<

rs.o: rs.cpp setup_socket.h iface.h nd_router.h eui64.h checksum.h
setup_socket.o: setup_socket.cpp setup_socket.h
nd_router.o: nd_router.cpp nd_router.h
iface.o: iface.cpp iface.h
eui64.o: eui64.cpp eui64.h
compose_ip6_hdr.o: compose_ip6_hdr.cpp compose_ip6_hdr.h
compose_icmp6_hdr.o: compose_icmp6_hdr.cpp compose_icmp6_hdr.h

checksum.o: checksum.c checksum.h

clean:
	rm -f *~ *.o $(EXEC) $(TEST_EXEC)

