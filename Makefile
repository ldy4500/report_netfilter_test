all: report_netfilter_test

report_netfilter_test : main.cpp
	g++ -o report_netfilter_test main.cpp -lnetfilter_queue

clean :
	rm -f report_netfilter_tet *.o
