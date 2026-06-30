import hashlib
import random

'''
MarkedBloomFilter is a Marked Bloom filter variant designed for the amnesia in the Bernoulli Honeywords system. 
It maintains a set B of indices corresponding to the real password and random decoys, ensuring that the real password's 
indices do not exceed a target size determined by the parameters b, k, and p_h. It also maintains a set M of marks, which mark 
the real password and the honeywords. Two parameters, p_mark and p_remark, determine the chance of a remarking happening,
and the chances of a word to be marked during the remarking. The filter provides methods to configure itself for a given 
hashed password and check for membership.
'''
class MarkedBloomFilter:
    def __init__(self, b, k, p_h, p_mark=0.95, p_remark=0.065):
        self.b = b # Marked Bloom filter size (number of bits)
        self.k = k # Number of hash functions
        self.p_h = p_h # Honeyword probability
        self.p_mark = p_mark # Marking rate
        self.p_remark = p_remark # Remarking rate

        self.target_B_size = round((p_h ** (1.0 / k)) * b) # Target size for set B

        self.B = set() # Set of indices in the Marked Bloom filter
        self.M = set() # Set of marks in the Marked Bloom filter
        self.F = self._generate_hash_functions() # List of hash functions for the Marked Bloom filter

    '''
    Function that generates the list of hash functions for the Marked Bloom filter.
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
    Function that creates a Marked Bloom filter for an account.
    '''
    def create_mbf_for_account(self, hashed_password):
        self.B = set()
 
        real_indices = self.get_indices_for_input(hashed_password) # Get indices of the real password
        self.B.update(real_indices) # Add the real password to B
 
        if len(self.B) > self.target_B_size:
            raise ValueError(
                f"Parameter conflict: |F(H(π̂))|={len(self.B)} already "
                f"exceeds target_B_size={self.target_B_size} "
                f"(b={self.b}, k={self.k}, p_h={self.p_h}). "
                f"Increase b or p_h, or decrease k."
            )

        # Fill the rest of B with random indices to add honeywords to the Bloom filter.
        while len(self.B) < self.target_B_size:
            self.B.add(random.randint(1, self.b))

        # Mark the real password in M
        self.M = set()
        self.M.update(real_indices) 

        # Mark the rest of the honeywords with probability p_mark
        for idx in self.B:
            if idx not in real_indices:
                if random.random() < self.p_mark:
                    self.M.add(idx)

    '''
    Membership test - check if the password is in B.
    '''
    def in_B(self, hashed_password):
        for f in self.F:
            if f(hashed_password) not in self.B:
                return False
        return True

    '''
    Membership test - check if the password is in M.
    '''
    def in_M(self, hashed_password):
        for f in self.F:
            if f(hashed_password) not in self.M:
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

    '''
    Function that marks the used password and other honeywords from the Marked Bloom filter.
    '''
    def remark(self, hashed_password):
        used_indices = self.get_indices_for_input(hashed_password)
        new_M = set()

        new_M.update(used_indices)

        for idx in self.B:
            if idx not in used_indices:
                if random.random() < self.p_mark:
                    new_M.add(idx)
 
        self.M = new_M

    '''
    Get a snapshot of M.
    '''
    def snapshot_M(self):
        return frozenset(self.M)