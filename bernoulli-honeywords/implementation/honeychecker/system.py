import os
import utils

from honeychecker.bloom import BloomFilter

'''
Server that holds the users' accounts with the username, salt and bloom filter.
'''
class HoneycheckerServer:
    def __init__(self):
        self.db = {}

    '''
    Function to save account in the server.
    '''
    def save_account(self, username, salt, bloom_filter):
        self.db[username] = {
            'salt': salt,
            'bloom': bloom_filter
        }

'''
Honeychecker that holds the indices of the true password for each account.
'''
class Honeychecker:
    def __init__(self):
        self.db = {}
    
    '''
    Function to save the indices of the true password for an account in the honeychecker.
    '''
    def save_true_indices(self, username, true_indices):
        self.db[username] = true_indices

    '''
    Verify if the input indices match the true indices. If not, return false.
    '''
    def verify(self, username, input_indices):
        true_indices = self.db.get(username)
        return input_indices == true_indices

'''
Honeychecker system with Bernoulli Honeywords.
'''
class HoneycheckerSystem:
    def __init__(self, b=128, k=20, p_h=0.01):
        self.server = HoneycheckerServer()
        self.honeychecker = Honeychecker()
        
        self.b = b
        self.k = k
        self.p_h = p_h

    '''
    Register user in the honeychecker system.
    '''
    def register_user(self, username, password):
        salt = os.urandom(16)
        hashed_pw = utils.hash_password(password, salt)
        
        user_bloom = BloomFilter(self.b, self.k, self.p_h)
        user_bloom.create_bf_for_account(hashed_pw)
        
        true_indices = user_bloom.get_indices_for_input(hashed_pw)
        
        self.server.save_account(username, salt, user_bloom) # Save account in the server.
        self.honeychecker.save_true_indices(username, true_indices) # Save password indices in honeychecker.

    '''
    Login user with input password. If the input password is not the real password, raise alarm.
    '''
    def login(self, username, password):
        if username not in self.server.db: # User is not registered.
            return "failure"
        
        account = self.server.db[username]
        salt = account['salt']
        user_bloom = account['bloom']
        
        hashed_attempt = utils.hash_password(password, salt)
        
        if not user_bloom.in_B(hashed_attempt): # Wrong password.
            return "failure"
        
        submitted_indices = user_bloom.get_indices_for_input(hashed_attempt)
        
        result = self.honeychecker.verify(username, submitted_indices)
        
        if result:
            return "success" # Input password is correct.
        else: 
            return "alarm" # Input password is honeyword.