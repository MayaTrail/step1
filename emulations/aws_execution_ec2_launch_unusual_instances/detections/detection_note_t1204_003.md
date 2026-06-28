# Detection Note — T1204.003 (Launch Unusual EC2 Instance Types for Cryptomining)

**Signal:** ec2:RunInstances with unusual instance types (GPU, high-compute) not in baseline; GuardDuty CryptoCurrency:EC2/BitcoinTool.B if mining traffic detected

**GuardDuty:** CryptoCurrency:EC2/BitcoinTool.B

See the sigma/kql rules in this directory (complete their TODO event names).
