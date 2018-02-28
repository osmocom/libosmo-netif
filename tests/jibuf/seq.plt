#set terminal png size 1280,1024 enhanced font "Helvetica,20"
#set output 'output.png'
#set terminal qt
#set output

set datafile separator "\t"
set datafile missing '0'

#set multiplot

# key/legend
set key top right
set key box
set key left bottom
set key bmargin


set title 'Jitter Graph'
set xlabel 'Timestamp'
set ylabel 'Seq'
set ytics nomirror

#set y2label 'delay [ms]'
#set y2tics nomirror

# For pcap based input, 'pre.delay' makes no sense (it's 0) as we can't know tx_delay
pcap = 1
if (pcap) {
        plot \
        '/tmp/bla' using 3:1 with linespoints title 'pre.trans' axes x1y1, \
        '/tmp/bla' using 4:1 with linespoints title 'post.trans' axes x1y1, \
        '/tmp/bla' using 3:7 with linespoints title 'pre.jitter' axes x1y1, \
        '/tmp/bla' using 4:8 with linespoints title 'post.jitter' axes x1y1, \
        '/tmp/bla' using 3:10 with linespoints title 'pre.buffer' axes x1y1, \
        '/tmp/bla' using 4:((column(4)-column(3))) with linespoints title 'post.delay' axes x1y1

} else {
        plot \
        '/tmp/bla' using 3:5 with linespoints title 'pre.trans' axes x1y1, \
        '/tmp/bla' using 4:6 with linespoints title 'post.trans' axes x1y1, \
        '/tmp/bla' using 3:7 with linespoints title 'pre.jitter' axes x1y1, \
        '/tmp/bla' using 4:8 with linespoints title 'post.jitter' axes x1y1, \
        '/tmp/bla' using 3:9 with linespoints title 'pre.dropped' axes x1y1, \
        '/tmp/bla' using 3:10 with linespoints title 'pre.buffer' axes x1y1, \
        '/tmp/bla' using 3:11 with linespoints title 'pre.skew' axes x1y1, \
        '/tmp/bla' using 3:((column(3)-column(2))) with linespoints title 'pre.delay' axes x1y1, \
        '/tmp/bla' using 4:((column(4)-column(2))) with linespoints title 'post.delay' axes x1y1
}

pause mouse close; exit
