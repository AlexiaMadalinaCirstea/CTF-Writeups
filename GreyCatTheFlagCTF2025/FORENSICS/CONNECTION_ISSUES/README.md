This is just a template, you don't need to follow it. Feel free to change it as you see fit.
## Name
Connection Issues
### Problem Description
We were provided with a chall.pcap file and tasked with extracting a hidden flag embedded within the packet capture. The challenge hinted at analyzing traffic, likely HTTP-based, and reconstructing fragmented data.
### Solution
Tools Used
----------
Wireshark (for initial manual inspection),
pyshark (Python wrapper for TShark),
Python + base64 + re (regex for decoding fragments),
TShark CLI (tshark.exe path explicitly set)

Investigation Strategy
----------------------
Initial Inspection:
Opening the .pcap in Wireshark revealed HTTP traffic with base64-looking data. These looked like fragmented messages possibly forming a flag.,

Scripted Extraction:
I built a Python script using pyshark to extract all payloads, search for base64 strings, decode them, and collect only those containing flag-relevant patterns.,

   Example logic:
   
   base64_regex = re.compile(r'\b[a-zA-Z0-9+/=]{8,24}\b')
   


Fragment Detection:
The script revealed multiple repeatable fragments like:
grey{d,
1d_1_j,
us7_ge,
7_p01s,
on3d},
,

   These appeared repeatedly across different packets.

Reconstruction Logic
--------------------
The script grouped decoded fragments and attempted permutations for reconstruction. Using logic and some filtering (prefix + suffix matching), O arrived at:

   grey{d1d_1_jus7_ge7_p01son3d}

Final Flag
----------
grey{d1d_1_jus7_ge7_p01son3d}


And here is the full code I used:
import os
import re
import base64
import pyshark

os.environ["PATH"] += os.pathsep + r"D:\Wireshark"
pcap_path = "chall.pcap"

print("[] Scanning for potential base64 fragments...")

capture = pyshark.FileCapture(pcap_path, include_raw=True, use_json=True, tshark_path=r"D:\Wireshark\tshark.exe")

fragments = []

base64_pattern = re.compile(r'[a-zA-Z0-9+/=]{8,}')

packet_num = 0
for packet in capture:
    try:
        raw = packet.get_raw_packet()
        text = raw.decode(errors="ignore")

        matches = base64pattern.findall(text)
        for match in matches:
            for pad in ["", "=", "=="]:
                try:
                    decoded = base64.b64decode(match + pad).decode("utf-8", errors="ignore")
                    if any(x in decoded for x in ['grey', '{', '}', '', 'flag']):
                        print(f"[Packet #{packet.number}] Match: {match} → {decoded}")
                        fragments.append(decoded)
                        break
                except:
                    continue
    except:
        continue

capture.close()

print("\n[] Attempting reconstruction from decoded fragments...")
flag_candidates = set()

for i in range(len(fragments)):
    for j in range(i + 1, len(fragments)):
        combined = fragments[i] + fragments[j]
        if 'grey{' in combined and '}' in combined:
            maybe_flag = re.findall(r'grey{[^}]+}', combined)
            for flag in maybe_flag:
                flag_candidates.add(flag)

if flag_candidates:
    print("\nGuessed flag(s):")
    for flag in flag_candidates:
        print(flag)
else:
    print("No valid flags reconstructed.")
