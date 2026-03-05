```bash
sudo python3 mininet_HW.py --duration 25 --lam 800,500,300 --p_s2_s3 0.3 --p_s2_s4 0.7 --p_s3_s5 0.8 --p_s3_s6 0.2 --r_s1_s3 10 --r_s2_s3 6 --r_s2_s4 8 --d_s2_s4 10 --r_s3_s5 8 --r_s3_s6 4 --d_s3_s6 20 --r_s4_s6 10 --results results4 --r_s5_h4 20 --r_s6_h5 30



```



nodes 
net 
dump
sh ovs-ofctl -O OpenFlow13 dump-flows s2 # test group at s2
sh ovs-ofctl -O OpenFlow13 dump-flows s3 # test group at s3 
sh ovs-ofctl -O OpenFlow13 dump-groups s2

sudo mn -c  if error with Ctrl+C