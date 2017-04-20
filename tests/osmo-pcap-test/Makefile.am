include $(top_srcdir)/Make_global.am

check_PROGRAMS = osmo-pcap-test

osmo_pcap_test_SOURCES = proto.c		\
			 l2_eth.c		\
			 l2_sll.c		\
			 l3_ipv4.c		\
			 l4_tcp.c		\
			 l4_udp.c		\
			 osmux_test.c		\
			 pcap.c

osmo_pcap_test_LDADD =   -lpcap			\
			 -losmocore		\
			 -losmonetif
