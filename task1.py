import sys
from typing import List, Dict, Any
import hashlib

# To simulate k independent hash functions h_i(x), we use the double hashing technique:
# h_i(x) = (h1(x) + i * h2(x)) mod m
# where h1 and h2 are two different hash functions.

class BloomFilter:
    """
    Bloom filter implementation for efficient element existence checking 
    with minimal memory usage.
    
    Technical specifications:
    - size (m): Size of the bit array.
    - num_hashes (k): Number of hash functions.
    """
    def __init__(self, size: int, num_hashes: int):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("Size must be a positive integer.")
        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("Number of hashes must be a positive integer.")

        self.size = size  # Size of the bit array (m)
        self.num_hashes = num_hashes  # Number of hash functions (k)
        # We use a simple list of zeros/ones as the bit array
        self.bit_array: List[int] = [0] * size

    def _get_indices(self, item: str) -> List[int]:
        """
        Generates k indices for the given item using double hashing.
        The password is converted to its byte representation.
        """
        if not item:
            raise ValueError("Item (password) cannot be empty.")

        item_bytes = item.encode('utf-8')

        # H1: Use SHA-256 for the first hash
        h1 = int(hashlib.sha256(item_bytes).hexdigest(), 16)
        
        # H2: Use SHA-1 for the second hash to ensure independence
        h2 = int(hashlib.sha1(item_bytes).hexdigest(), 16)

        indices: List[int] = []
        for i in range(1, self.num_hashes + 1):
            # Double hashing formula: h_i(x) = (h1 + i * h2) mod m
            index = (h1 + i * h2) % self.size
            indices.append(index)
            
        return indices

    def add(self, item: str):
        """
        Adds an item (password) to the Bloom filter. Sets the corresponding bits to 1.
        Handles incorrect data types.
        """
        if not isinstance(item, str):
            raise TypeError(f"Item to add must be a string, got {type(item).__name__}.")
        
        try:
            indices = self._get_indices(item)
            for index in indices:
                self.bit_array[index] = 1
        except ValueError as e:
            # Handling empty string
            print(f"Error adding item '{item}': {e}")
            return

    def check(self, item: str) -> bool:
        """
        Checks for the presence of an item (password) in the Bloom filter.
        Returns True if the item is likely present (may be a False Positive).
        Returns False if the item is definitely not present.
        """
        if not isinstance(item, str):
            raise TypeError(f"Item to check must be a string, got {type(item).__name__}.")
            
        try:
            indices = self._get_indices(item)
            for index in indices:
                if self.bit_array[index] == 0:
                    return False  # If at least one bit is not set, the item is definitely not present
            return True  # All bits are set, the item is likely present
        except ValueError:
            # Handling empty string
            return False


def check_password_uniqueness(filter: BloomFilter, new_passwords: List[Any]) -> Dict[str, str]:
    """
    Checks the list of new passwords for uniqueness using the passed Bloom filter.
    
    Parameters:
    - filter: An instance of BloomFilter containing previously used passwords.
    - new_passwords: List of passwords to check.
    
    Returns:
    Dictionary {password: status}, where status is 'already used' or 'unique'.
    """
    if not isinstance(new_passwords, list):
         raise TypeError("The list of passwords must be of type List.")
         
    results: Dict[str, str] = {}
    
    for password_input in new_passwords:
        # Handling incorrect or empty values
        if not isinstance(password_input, str) or not password_input:
             key = str(password_input)
             results[key] = "Invalid/empty password"
             continue

        password = password_input
        
        try:
            # Checking password presence in the filter
            is_used = filter.check(password)
        except TypeError:
            # This case should be covered by the check above, but added for robustness
            results[password] = "Invalid data type"
            continue
        
        if is_used:
            results[password] = "already used"
        else:
            results[password] = "unique"
            
    return results

if __name__ == "__main__":
    print("Task 1. Checking password uniqueness using a Bloom filter\n")
    
    # Initializing the Bloom filter
    # Note: for 1000 items and 3 hashes, the False Positive Rate (FPR) is ~0.003
    bloom = BloomFilter(size=1000, num_hashes=3) 

    # Adding existing passwords
    existing_passwords = ["password123", "admin123", "qwerty123"]
    print(f"1. Adding existing passwords to the filter: {existing_passwords}")
    
    # Example of error handling during addition
    try:
        bloom.add(123) # This will trigger a TypeError
    except TypeError as e:
        print(f"   [Error Handling] {e}")

    for password in existing_passwords:
        bloom.add(password)
        
    print("-" * 30)
    
    # Checking new passwords
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest", "", None]
    print(f"2. Checking the list of new passwords: {new_passwords_to_check}")
    
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Displaying results
    print("\nVerification Results:")
    for password, status in results.items():
        print(f"Password '{password}' — {status}.")