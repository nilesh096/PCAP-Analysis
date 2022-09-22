# PCAP-Analysis
Analyzing a Wireshark/TCPdump trace to characterize the TCP flows in the trace


# Additive Increase, Additive Decrease (AIAD)
 

In the above diagram, the x axis represents flow 1 throughput and the y axis represents flow 2 throughput. The x=y line is called the fairness line and the mid point is called the best operating or the fairness point. If the additive increase and additive decrease approach for TCP cwnd adjustment is adopted, then from the graph we can see that there wouldn’t be equal sharing of the bandwidth possible. This is due to the fact that if we assume the initial cwnd to be at (40,80), then after the first additive decrease, the cwnd would be at (20,60) i.e decrease of 20 and after some time, the additive increase will increase the cwnd by 20 again to (40,80). So we can see that with AIAD approach the cwnd will keep on oscillating between 2 points and will never reach the fairness point. Thus, this approach can’t be used to ensure fairness


![image](https://user-images.githubusercontent.com/17272682/191856190-f592fccf-1f53-45ea-82f5-66767e765d45.png)


#	Multiplicative Increase, Multiplicative Decrease (MIMD)
 

As seen earlier in AIAD case, the same problem would occur in MIMD approach that the cwnd would keep on oscillating between the two points i.e in this case (40,90) and (20,45). Hence, cwnd would never approach the fairness point and thus this approach wouldn’t be fair.

![image](https://user-images.githubusercontent.com/17272682/191856284-cc2acbbc-525d-43f0-8d58-ab1428fa5823.png)


# Multiplicative Increase, Additive Decrease (MIAD)

In this approach, we assume the cwnd is initially at (40,70). At this point, the cwnd would have to decrease, due to additive decrease and will be at (30,50). Now that the cwnd can be increased say, by factor of 2, so now the cwnd would be (60,100). As this sequence of multiplicative increase and additive decrease goes on, we see that the point going farther and farther away from the fairness point. Thus, we can prove that this approach would be unfair. 

![image](https://user-images.githubusercontent.com/17272682/191856319-0fda993e-892a-469e-84f3-1cc6934ed960.png)


