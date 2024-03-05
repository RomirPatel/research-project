import subprocess

# Step 1: Convert Wireshark capture file to a format Zeek can analyze
def convert_capture_file(input_file, output_file):
    try:
        subprocess.run(["editcap", "-F", "pcap", input_file, output_file])
        # You can also use tshark or other tools to convert to pcapng format if needed
    except Exception as e:
        print(f"Error converting capture file: {e}")

# Step 2: Run Zeek on the converted capture file
def run_zeek(input_file):
    try:
        subprocess.run(["zeek", "-r", input_file])
    except Exception as e:
        print(f"Error running Zeek: {e}")

# Example usage
input_capture_file = "input.pcap"
output_pcap_file = "output.pcap"

# Convert capture file
convert_capture_file(input_capture_file, output_pcap_file)

# Run Zeek
run_zeek(output_pcap_file)
