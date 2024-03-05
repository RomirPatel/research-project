from scapy.all import rdpcap
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Load pcap data and extract features
pcap = rdpcap("test.pcapng")
features = []
labels = []  # Assuming you have labels for threat or non-threat

for pkt in pcap:

    def determine_if_threat():
        print()
        
    
    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        protocol = pkt["IP"].proto
        length = len(pkt)
        payload = len(pkt.payload) if pkt.payload else 0
        
        # Assuming you have a function to determine if the packet is a threat
        is_threat = determine_if_threat(pkt)  # You need to implement this function
        
        features.append([src_ip, dst_ip, protocol, length, payload])
        labels.append(is_threat)




# Create DataFrame
data = pd.DataFrame(features, columns=["src_ip", "dst_ip", "protocol", "length", "payload"])
data['is_threat'] = labels

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(data.drop('is_threat', axis=1), data['is_threat'], test_size=0.2, random_state=42)

# Train Random Forest classifier
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Evaluate the model
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Make predictions on new data
new_pcap = rdpcap("new_test.pcapng")
new_features = []

for pkt in new_pcap:
    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        protocol = pkt["IP"].proto
        length = len(pkt)
        payload = len(pkt.payload) if pkt.payload else 0
        
        new_features.append([src_ip, dst_ip, protocol, length, payload])

# Create DataFrame for new data
new_data = pd.DataFrame(new_features, columns=["src_ip", "dst_ip", "protocol", "length", "payload"])

# Predict threats
new_data['is_threat'] = clf.predict(new_data)

# Filter packets based on predicted threats
threat_packets = new_data[new_data['is_threat'] == 1]
print(threat_packets[['src_ip', 'dst_ip', 'protocol']])
