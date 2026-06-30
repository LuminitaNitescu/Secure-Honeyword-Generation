import os
import random
import utils

from amnesia.local.marked_bloom import MarkedBloomFilter

'''
Server that holds the users' accounts with the username, salt and bloom filter.
'''
class AmnesiaServer:
    def __init__(self):
        self.db = {}

    '''
    Function to save account in the server.
    '''
    def save_account(self, username, salt, bloom_filter):
        self.db[username] = {
            "salt": salt, 
            "bloom": bloom_filter
        }

'''
Amnesia system with Bernoulli honeywords.
'''
class AmnesiaSystem:
    def __init__(self, b=128, k=20, p_h=0.01, p_mark=0.95, p_remark=0.065):
        self.server = AmnesiaServer()

        self.b = b
        self.k = k
        self.p_h = p_h
        self.p_mark = p_mark
        self.p_remark = p_remark
    
    '''
    Register users in the Amnesia system.
    '''
    def register_user(self, username, password):
        salt = os.urandom(16)
        hashed_pw = utils.hash_password(password, salt)
        
        user_bloom = MarkedBloomFilter(self.b, self.k, self.p_h, self.p_mark, self.p_remark)
        user_bloom.create_mbf_for_account(hashed_pw)

        self.server.save_account(username, salt, user_bloom) # Save account in the server.
    
    '''
    Login user with input password. If input password is not marked, raise an alarm. Trigger a remarking with probability p_remark.
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

        if user_bloom.in_M(hashed_attempt):
            if random.random() < self.p_remark: # Trigger remark with probability p_remark if input password is marked.
                user_bloom.remark(hashed_attempt)
            return "success" # Input password is marked.
        else:
            return "alarm" # input password is not marked.

    '''
    Legitimate login by the user of the account. Returns a snapshot of M after the login.
    '''
    def legitimate_login(self, username, real_password):
        result = self.login(username, real_password)
        account = self.server.db.get(username)
        m_snapshot = account["bloom"].snapshot_M() if account else None
        return result, m_snapshot