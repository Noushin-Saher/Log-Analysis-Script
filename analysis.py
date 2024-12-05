import re
import csv
import os
from collections import defaultdict

# File paths for input log file and output CSV
LOG_FILE_PATH = '../data/logfile.log'
OUTPUT_FILE_PATH = '../data/log_analysis_results.csv'

# Analyze request counts grouped by IP address
def analyze_requests_by_ip(log_lines):
    ip_request_counts = defaultdict(int)
    for line in log_lines:
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip_request_counts[match.group(1)] += 1
    # Return sorted IP addresses by request count (descending)
    return sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)

# Determine the most frequently accessed endpoint
def get_most_frequent_endpoint(log_lines):
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        match = re.search(r'"[A-Z]+\s(/[^ ]*)', line)
        if match:
            endpoint_counts[match.group(1)] += 1
    # Retrieve the endpoint with the highest count
    return max(endpoint_counts.items(), key=lambda x: x[1], default=None)

# Identify IPs with failed login attempts exceeding the threshold
def flag_suspicious_logins(log_lines, fail_threshold=10):
    failed_attempts = defaultdict(int)
    for line in log_lines:
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+).*"\w+\s[^\s]+\sHTTP/1\.\d"\s(\d+)', line)
        if match and match.group(2) == '401':  # HTTP 401 indicates unauthorized access
            failed_attempts[match.group(1)] += 1
    # Return IPs with failed attempts above the threshold
    return [(ip, count) for ip, count in failed_attempts.items() if count >= fail_threshold]

# Write analysis results to a CSV file
def save_results_to_csv(ip_counts, top_endpoint, suspicious_ips):
    with open(OUTPUT_FILE_PATH, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        # Section: Request Counts by IP
        writer.writerow(['Requests by IP:'])
        writer.writerow([])
        writer.writerow(['IP Address          Request Count'])
        writer.writerow([])
        for ip, count in ip_counts:
            writer.writerow([f"{ip:<20}{count:<10}"])
        writer.writerow([])

        # Section: Most Accessed Endpoint
        writer.writerow(['Most Frequently Accessed Endpoint:'])
        if top_endpoint:
            writer.writerow([f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)"])
        else:
            writer.writerow(['None (Accessed 0 times)'])
        writer.writerow([])

        # Section: Suspicious Login Activity
        writer.writerow(['Suspicious Activity Detected:'])
        writer.writerow(['IP Address           Failed Login Attempts'])
        if suspicious_ips:
            for ip, count in suspicious_ips:
                writer.writerow([f"{ip:<20}{count}"])
        else:
            writer.writerow(['None                 0'])
        writer.writerow([])

# Main function to coordinate the analysis process
def main():
    if not os.path.isfile(LOG_FILE_PATH):
        print(f"Error: Log file not found at {LOG_FILE_PATH}")
        return

    try:
        # Read log data
        with open(LOG_FILE_PATH, 'r') as log_file:
            log_lines = log_file.readlines()
        
        # Perform analyses
        ip_analysis = analyze_requests_by_ip(log_lines)
        most_frequent_endpoint = get_most_frequent_endpoint(log_lines)
        suspicious_logins = flag_suspicious_logins(log_lines)

        # Display results
        print("Request Counts by IP Address:")
        for ip, count in ip_analysis:
            print(f"{ip:<20}{count}")
        
        print("\nMost Frequently Accessed Endpoint:")
        if most_frequent_endpoint:
            print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")
        else:
            print("No endpoint data available.")
        
        print("\nSuspicious Login Activity:")
        if suspicious_logins:
            print(f"{'IP Address':<20}{'Failed Attempts'}")
            for ip, count in suspicious_logins:
                print(f"{ip:<20}{count}")
        else:
            print("No suspicious activity detected.")
        
        # Save results
        save_results_to_csv(ip_analysis, most_frequent_endpoint, suspicious_logins)
        print(f"Results have been saved to: {OUTPUT_FILE_PATH}")

    except Exception as e:
        print(f"An error occurred during analysis: {e}")

if __name__ == "__main__":
    main()
