import random
import hashlib

'''
BloomFilter is a Bloom filter variant designed for the honeychecker in the Bernoulli Honeywords system. 
It maintains a set B of indices corresponding to the real password and random decoys, ensuring that the real password's 
indices do not exceed a target size determined by the parameters b, k, and p_h. The filter provides methods to 
configure itself for a given hashed password and check for membership.
'''
class BloomFilter:
    def __init__(self, b, k, p_h):
        self.b = b # Bloom filter size (number of bits)
        self.k = k # Number of hash functions
        self.p_h = p_h # # Honeyword probability
        
        self.target_B_size = round((p_h ** (1.0 / k)) * b) # Target size for set B
        
        self.B = set() # Set of indices in the Bloom filter
        self.F = self._generate_hash_functions() # List of hash functions for the Bloom filter

    '''
    Function that generates the list of hash functions for the Bloom filter.
    '''
    def _generate_hash_functions(self):
        def make_hash_func(seed):
            def hash_func(hashed_password):
                data = f"{seed}:{hashed_password}".encode("utf-8")
                hex_digest = hashlib.sha256(data).hexdigest()
                return (int(hex_digest, 16) % self.b) + 1
            return hash_func
        return [make_hash_func(i) for i in range(self.k)]

    '''
    Function that creates a Bloom filter for an account.
    '''
    def create_bf_for_account(self, hashed_password):
        self.B = set()

        real_indices = self.get_indices_for_input(hashed_password) # Get indices of the real password
        self.B.update(real_indices) # Add the real password to B

        # Guard: real password alone must not exceed the target size.
        if len(self.B) > self.target_B_size:
            raise ValueError(
                f"Parameter conflict: inserting the real password's indices "
                f"gives |B|={len(self.B)}, which already exceeds "
                f"target_B_size={self.target_B_size} "
                f"(b={self.b}, k={self.k}, p_h={self.p_h}). "
                f"Increase b or p_h, or decrease k."
            )

        # Fill the rest of B with random indices to add honeywords to the Bloom filter.
        while len(self.B) < self.target_B_size:
            self.B.add(random.randint(1, self.b))

    '''
    Membership test - check if the password is in B.
    '''
    def in_B(self, hashed_password):
        for f in self.F:
            if f(hashed_password) not in self.B:
                return False
        return True
    
    '''
    Get the indices of an input password.
    '''
    def get_indices_for_input(self, hashed_input):
        indices = set()
        for f in self.F:
            indices.add(f(hashed_input))
        return indices
    