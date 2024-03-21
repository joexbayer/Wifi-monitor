1. Error Rates (Retransmissions):
Retransmissions in Wi-Fi are a response to packet loss, which can be due to interference, signal attenuation, or other issues. Measuring error rates involves:

Capturing Data Frames: Focus on capturing data frames, particularly those that indicate a retransmission. In the 802.11 MAC header, there is a 'Retry' flag that indicates if a frame is a retransmission.
Counting Retries: For each captured frame, check the Retry flag. Increment a counter for retransmissions for the respective AP (identified by BSSID).
Calculating Error Rate: Error rate can be expressed as the ratio of retransmitted frames to the total number of transmitted frames. For each AP, calculate this ratio over a given time period.

2. Channel Utilization:
Channel utilization is a measure of how much a channel is being used, which can affect performance due to co-channel and adjacent-channel interference. To measure this:

Monitor All Channels: Temporarily scan and capture packets on all channels. This might require your scanning tool to hop between channels.
Count Frames Per Channel: Keep a count of the number of frames and their sizes for each channel. This will give you an idea of the traffic volume on each channel.
Calculate Utilization: Channel utilization can be calculated as a percentage of time the channel is being used. This is more complex as it involves not only the number of packets but also their lengths and the data rates at which they are transmitted.
Detect Overlapping Channels: Especially in the 2.4 GHz band, channels overlap (e.g., Channel 1 overlaps with Channels 2-5). Analyze the utilization of overlapping channels to assess interference.