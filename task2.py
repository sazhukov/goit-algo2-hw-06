import re
import time
import math
import hashlib
import random
import json
from typing import List, Optional, Tuple, Dict, Any
import os # Added to check for file existence

# 1. LOADING DATA FROM FILE

def read_log_file(filepath: str) -> List[str]:
    """
    Reads lines from the log file. Each line must be a separate JSON object.
    """
    print(f"Reading data from file: {filepath}...")
    
    # Check for file existence
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found in the current directory. Please create it.")
        return []
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Read all lines. Each line is a JSON object.
            log_data = f.readlines()
        print(f"Read {len(log_data)} lines.")
        return log_data
    except Exception as e:
        print(f"Error reading the file: {e}")
        return []

def load_ip_addresses(log_data: List[str]) -> List[str]:
    """
    Loads IP addresses from the JSON-formatted log file, ignoring incorrect lines.
    The IP address is extracted from the "remote_addr" field.
    (Acceptance Criterion 1)
    """
    print("Parsing IP addresses from JSON log (field 'remote_addr')...")
    ips = []
    
    for line in log_data:
        # Remove extra spaces or newlines if present
        line = line.strip()
        if not line:
            continue
            
        try:
            # Attempt to parse the line as JSON
            data = json.loads(line)
            
            # Check for the presence of the "remote_addr" key and add it
            if "remote_addr" in data:
                ips.append(data["remote_addr"])
                
        except json.JSONDecodeError:
            # Ignore lines that are not valid JSON
            continue
    
    print(f"Number of successfully extracted IP addresses for analysis: {len(ips)}")
    return ips

# 2. EXACT COUNTING (SET)

def exact_count(ip_list: List[str]) -> Tuple[int, float]:
    """
    Exact counting of unique IP addresses using a set.
    (Acceptance Criterion 2)
    """
    start_time = time.perf_counter()
    unique_ips = set(ip_list)
    count = len(unique_ips)
    end_time = time.perf_counter()
    return count, end_time - start_time

# 3. APPROXIMATE COUNTING (HYPERLOGLOG)

class HyperLogLog:
    """
    Approximate counting of unique elements using the HyperLogLog algorithm.
    """
    def __init__(self, p: int = 14):
        """
        HLL initialization.
        p (precision): The number of bits used for the register index.
        m: The number of registers (m = 2^p).
        """
        if not (4 <= p <= 16):
            raise ValueError("Precision p must be between 4 and 16.")
            
        self.p = p
        self.m = 1 << p  # 2^p
        self.registers = [0] * self.m  # Bits to store the maximum rank
        
        # Correction constant (alpha), dependent on m
        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else: # m >= 128
            self.alpha = 0.7213 / (1 + 1.079 / self.m)

    def _hash(self, item: str) -> int:
        """Uses SHA-1 to get a 160-bit hash (as a strong source of randomness)."""
        # Hash the string and return the first 32 bits as an integer
        hash_val = hashlib.sha1(item.encode('utf-8')).digest()
        # Convert the first 4 bytes to int (for index and bitwise operations)
        return int.from_bytes(hash_val[:4], byteorder='big')

    def add(self, item: str):
        """Adds an item to the HLL."""
        hash_val = self._hash(item)
        
        # Determine the register index (first p bits of the hash)
        register_index = hash_val >> (32 - self.p)
        
        # Determine the remaining part of the hash (32 - p bits)
        # Use 1-base indexing for rank: 
        # rank(w) = position of the first one, counting from the end (as in Redis/standard HLL)
        
        # Remaining hash - bits used for rank counting
        remaining_bits = hash_val & ((1 << (32 - self.p)) - 1)
        
        # Find the rank (position of the first one, counting from the left, 1-based)
        if remaining_bits == 0:
            rank = 32 - self.p + 1 # If zeros until the end
        else:
            rank = (32 - self.p) - remaining_bits.bit_length() + 1
            
        # Update the register
        self.registers[register_index] = max(self.registers[register_index], rank)

    def count(self) -> float:
        """
        Returns the approximate number of unique elements (E) based on the harmonic mean.
        (Acceptance Criterion 3)
        """
        # Calculating the harmonic mean
        sum_of_inverse = sum(2**(-register_value) for register_value in self.registers)
        estimated_cardinality = self.alpha * (self.m ** 2) / sum_of_inverse

        # Small range correction (Linear Counting) and large range correction (Saturation Correction)
        
        # Zeros (Linear Counting for small ranges)
        V = self.registers.count(0)
        
        if estimated_cardinality <= 2.5 * self.m:
            # Small value correction (Linear Counting)
            if V != 0:
                estimated_cardinality = self.m * math.log(self.m / V)
            # If V == 0, standard counting is applied
        
        # Large value correction (Saturation Correction - for 32-bit hashes)
        # Not applied in this simplified model, as 32 bits only hash up to 2^32 unique elements, 
        # and the harmonic mean is already quite good.

        return estimated_cardinality


def hll_count(ip_list: List[str], p: int = 14) -> Tuple[float, float]:
    """Approximate counting using HyperLogLog."""
    start_time = time.perf_counter()
    
    # Create an HLL instance with precision p=14 (m=16384 registers), which gives an error of ~0.81%
    hll = HyperLogLog(p=p)
    
    for ip in ip_list:
        hll.add(ip)
        
    count = hll.count()
    
    end_time = time.perf_counter()
    return count, end_time - start_time

# 4. PERFORMANCE COMPARISON

def compare_performance(ip_list: List[str]):
    """
    Performs a comparison of exact and approximate counting.
    (Acceptance Criterion 4)
    """
    if not ip_list:
        print("\nCannot perform comparison: the list of IP addresses is empty.")
        return
        
    print("\n--- Performing Performance Comparison ---")

    # 1. Exact Counting
    exact_res, exact_time = exact_count(ip_list)
    print(f"Exact Counting completed in {exact_time:.4f} sec.")

    # 2. HyperLogLog Counting (using p=14 by default)
    hll_res, hll_time = hll_count(ip_list, p=14)
    
    # To correctly display the HLL size, its instance must be obtained
    temp_hll = HyperLogLog(p=14) 
    print(f"HyperLogLog (p={temp_hll.p}, {temp_hll.m} registers) completed in {hll_time:.4f} sec.")

    # 3. Displaying Results
    print("\n" + "=" * 50)
    print("Comparison Results:")
    
    # Creating the table
    table = {
        "Exact Counting": {"Unique Elements": exact_res, "Execution Time (sec.)": exact_time},
        "HyperLogLog": {"Unique Elements": hll_res, "Execution Time (sec.)": hll_time},
    }
    
    # Output formatting (as in the example)
    header = f"{'':<25} {'Exact Counting':>20} {'HyperLogLog':>20}"
    print(header)
    print("-" * len(header))
    
    # Displaying unique elements
    exact_count_formatted = f"{table['Exact Counting']['Unique Elements']:>20.1f}"
    hll_count_formatted = f"{table['HyperLogLog']['Unique Elements']:>20.1f}"
    print(f"{'Unique Elements':<25} {exact_count_formatted} {hll_count_formatted}")
    
    # Displaying execution time
    exact_time_formatted = f"{table['Exact Counting']['Execution Time (sec.)']:>20.4f}"
    hll_time_formatted = f"{table['HyperLogLog']['Execution Time (sec.)']:>20.4f}"
    print(f"{'Execution Time (sec.)':<25} {exact_time_formatted} {hll_time_formatted}")
    
    print("\n" + "=" * 50)
    
    # Error Analysis
    absolute_error = abs(exact_res - hll_res)
    relative_error = absolute_error / exact_res * 100 if exact_res else 0
    
    print(f"Exact number of unique IPs: {exact_res}")
    print(f"HLL Estimate: {hll_res:.2f}")
    print(f"HLL Relative Error: {relative_error:.2f}% (usually < 1%)")


if __name__ == "__main__":
    # Path to the log file
    LOG_FILE_PATH = "lms-stage-access.log"

    # 1. Load data
    log_lines = read_log_file(LOG_FILE_PATH)
    
    if log_lines:
        # 2. Parse IP addresses
        ip_addresses = load_ip_addresses(log_lines)
        
        # 3. Comparison
        compare_performance(ip_addresses)
    else:
        print("Cannot continue the analysis because the log file is empty or was not found. Please ensure the file exists and contains data.")
