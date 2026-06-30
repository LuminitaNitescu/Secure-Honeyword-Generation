#!/usr/bin/env python3

########################################################################################
#
# Name: Honeyword Generator
#  --Generate honeywords, (synthetic passwords), from a PCFG grammar
#
#  Written by Matt Weir
#
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#
#  Contact Info: cweir@vt.edu
#
#  honeyword_gen.py
#
#########################################################################################

##--Including this to print error message if python < 3.0 is used
from __future__ import print_function
import sys
###--Check for python3 and error out if not--##
if sys.version_info[0] < 3:
    print("This program requires Python 3.x", file=sys.stderr)
    sys.exit(1)
    
import argparse
import os  ##--Used for file path information
import random
from distutils.version import LooseVersion  #--Compare the trainer version used to generate the ruleset

#Custom modules
from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_manager.file_io import load_grammar
from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_manager.core_grammar import PcfgClass
from legacy_pcfg_master.python_pcfg_cracker_version3.pcfg_manager.markov_cracker import MarkovCracker
from util import special_char_converter

from util import UserData
import multiprocessing
from tqdm import tqdm
from itertools import zip_longest

import math

####################################################
# Simply parses the command line
####################################################
def parse_command_line(runtime_options):
    
    parser = argparse.ArgumentParser(
            description='Honeyword Generator: Generates honeywords, (synthetic passwords), from a PCFG grammar'
        )
        
    parser.add_argument(
            '--rule',
            '-r', 
            help='The rule set to use. Default: (%(default)s)',
            metavar='RULE_SET',
            required=False, 
            default= runtime_options['rule_name']
        )
        
    parser.add_argument(
            '--num_honeywords',
            '-n', 
            help='Number of honeywords to generate. Default: (%(default)s)',
            metavar='NUM_HONEYWORDS', 
            required=False,
            type=int, 
            default=runtime_options['num_honeywords']
        )
    
    try:
        args=parser.parse_args()
        runtime_options['rule_name'] = args.rule
        runtime_options['num_honeywords'] = args.num_honeywords
        
    except Exception as msg:
        print(msg, file=sys.stderr)
        return False

    ##--Perform some sanity checks on the input
    if runtime_options['num_honeywords'] <= 0:
        print("Error, you need to have a value greater than 0", file=sys.stderr)
        return False
        
        
    return True 

  
###################################################################################
# Prints the startup banner when this tool is run
###################################################################################
def print_banner(program_details):
    print('',file=sys.stderr)
    print ("Honeyword Generator version " + program_details['Version'], file=sys.stderr)
    print ("Written by " + program_details['Author'], file=sys.stderr)
    print ("Sourcecode available at " + program_details['Source'], file=sys.stderr)
    print('',file=sys.stderr)


####################################################################################
# ASCII art for displaying an error state before quitting
####################################################################################
def print_error():
    print('',file=sys.stderr)
    print('An error occured, shutting down',file=sys.stderr)
    print('',file=sys.stderr)
    print(r' \__/      \__/      \__/      \__/      \__/      \__/          \__/',file=sys.stderr)
    print(r' (oo)      (o-)      (@@)      (xx)      (--)      (  )          (OO)',file=sys.stderr)
    print(r'//||\\    //||\\    //||\\    //||\\    //||\\    //||\\        //||\\',file=sys.stderr)
    print(r'  bug      bug       bug/w     dead      bug       blind      bug after',file=sys.stderr)
    print(r'         winking   hangover    bug     sleeping    bug     whatever you did',file=sys.stderr)
    print('',file=sys.stderr)

  
##################################################################
# Main function, not that exciting
##################################################################
def main():
    
    ##--Information about this program--##
    management_vars = {
        ##--Information about this program--##
        'program_details':{
            'Program':'honeyword_gen.py',
            ##--I know, I skipped a couple of versions but want to keep this synced with pcfg_manager
            'Version': '3.3 Beta',
            'Author':'Matt Weir',
            'Contact':'cweir@vt.edu',
            'Source':'https://github.com/lakiw/pcfg_cracker'
        },
        ##--Runtime specific values, can be overriden via command line options
        'runtime_options':{
            'rule_name':'Default',
            #Number of honeywords to generate
            'num_honeywords':1
        }
    }  
       
    ##--Print out banner
    print_banner(management_vars['program_details'])
    
    ##--Parse the command line ---##
    if parse_command_line(management_vars['runtime_options']) != True:
        return
   
    ##--Specify where the rule file is located
    rule_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)),'Rules', 
        management_vars['runtime_options']['rule_name'])    
   
    ##--Initialize the grammar--##
    grammar = []
    config_details = {}
    if load_grammar(rule_directory, grammar, config_details) != True:
        print ("Error loading the PCFG grammar, exiting",file=sys.stderr)
        print_error()
        return
   
    ##--Load the Markov stats file--##
    ##--Only do this on newer grammars to ensure backwards compatability--##
    if LooseVersion(config_details['version']) >= LooseVersion("3.3"):
        try:
            markov_cracker = MarkovCracker(rule_directory)
        except:
            print ("Error loading the Markov stats file for the ruleset, exiting",file=sys.stderr)
            print_error()
            return
    else:
        markov_cracker = MarkovCracker()
 
    pcfg = PcfgClass(grammar, markov_cracker)

    ##--Generate the honeywords--##
    print("Generating Honeywords", file=sys.stderr)
    print("--------------------------------", file=sys.stderr)
    # First find the start index
    start_index = pcfg.start_index()
    if start_index == -1:
        print("Error with the grammar, could not find the start index", file=sys.stderr)
        return 
    
    ##--Number of honeywords left to generate
    ##--Errors can occur that prevent a honeyword from being displayed, (char encoding is a pain)
    ##--so this program needs to know that and then make more honeywords that can be displaced
    honeywords_left = management_vars['runtime_options']['num_honeywords']
    
    ##--If errrors occured, (used for debugging and warning users of this tool)
    errors_occured = 0
    
    ##--Generate each honeyword
    while honeywords_left >= 0:
        
        try:
            ##--Perform a weighted random walk of the grammar to get the parse tree
            parse_tree = pcfg.random_grammar_walk(start_index)
            honeyword = pcfg.gen_random_terminal(parse_tree)

            ##--Print the results
            ##--Note, this may throw an exception if the terminal it is printing to
            ##--doesn't support the character type. For example if a Cyrillic character
            ##--is printed on an English language Windows Command shell
            print(str(honeyword))
            honeywords_left = honeywords_left - 1
            
        except Exception as msg:
            errors_occured += 1
    
    if errors_occured != 0:
        print()
        if errors_occured == 1:
            print("Warning: " + str(errors_occured) + " error occured when trying to generate your honeywords")
        else:
            print("Warning: " + str(errors_occured) + " errors occured when trying to generate your honeywords")
            
        print("This is usually caused by your terminal not supporting the character encoding of a specific honeyword")
        print("For example, the honeyword may have contained a letter in a language your terminal doesn't support")
   
    return
    
if __name__ == "__main__":
    main()


_worker_pcfg = None

def _init_worker(pcfg):
    global _worker_pcfg
    _worker_pcfg = pcfg
    
def _generate_password(args):

    idx, cur_index = args

    local_errors = 0
    while True:
        try:
            parse_tree, p_structure = _worker_pcfg.random_grammar_walk(cur_index)
            password, p_replacements = _worker_pcfg.gen_random_terminal(parse_tree)
            
            if len(password) >= 1:
                return password, local_errors       
                
        except Exception as msg:
            local_errors += 1

def _generate_honeywords_for_single_password(args):

    idx, query, k, start_index, seed, replacement = args
    
    password = query[0]
    structure = query[1][0]
    structure_only_pii = query[1][1]
    pii = query[2]
    
    if replacement:
        pw_processed = password
    else:
        pw_processed = "".join(special_char_converter(structure_only_pii))   
    honeywords = [pw_processed]
    res = [[pw_processed, _worker_pcfg.get_prob(password, structure, start_index)]]
    
    cur_index = start_index
    local_errors = 0
    
    rng = random.Random(seed)
    
    while len(honeywords) < k:
        try:
            parse_tree, p_structure = _worker_pcfg.random_grammar_walk(cur_index)
            honeyword, p_replacements = _worker_pcfg.gen_random_terminal(pt=parse_tree, pii=pii, replacement=replacement)
            
            # print(str(honeyword))
            
            if (len(honeyword) >= 1 and honeyword not in honeywords):
                res.append([honeyword, math.exp(p_structure + p_replacements)])
                honeywords.append(honeyword)
                
        except Exception as msg:
            local_errors += 1
    
    rng.shuffle(res)
            
    return [pw_processed, res], local_errors

def generate(k, rule_name, queries: list=None, seed: int=None, mode="honeywords", replacement: bool = True):
    
    ##--Information about this program--##
    management_vars = {
        ##--Information about this program--##
        'program_details':{
            'Program':'honeyword_gen.py',
            ##--I know, I skipped a couple of versions but want to keep this synced with pcfg_manager
            'Version': '3.3 Beta',
            'Author':'Matt Weir',
            'Contact':'cweir@vt.edu',
            'Source':'https://github.com/lakiw/pcfg_cracker'
        },
    }  
       
    ##--Print out banner
    # print_banner(management_vars['program_details'])
   
    ##--Specify where the rule file is located
    rule_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)),'Rules', 
        rule_name)    
   
    ##--Initialize the grammar--##
    grammar = []
    config_details = {}
    if load_grammar(rule_directory, grammar, config_details) != True:
        print ("Error loading the PCFG grammar, exiting",file=sys.stderr)
        print_error()
        return
   
    ##--Load the Markov stats file--##
    ##--Only do this on newer grammars to ensure backwards compatability--##
    if LooseVersion(config_details['version']) >= LooseVersion("3.3"):
        try:
            markov_cracker = MarkovCracker(rule_directory)
        except:
            print ("Error loading the Markov stats file for the ruleset, exiting",file=sys.stderr)
            print_error()
            return
    else:
        markov_cracker = MarkovCracker()
 
    pcfg = PcfgClass(grammar, markov_cracker)

    ##--Generate the honeywords--##
    print("Generating Honeywords", file=sys.stderr)
    print("--------------------------------", file=sys.stderr)
    # First find the start index
    start_index = pcfg.start_index()
    if start_index == -1:
        print("Error with the grammar, could not find the start index", file=sys.stderr)
        return 
    
    ##--If errrors occured, (used for debugging and warning users of this tool)
    errors_occured = 0
    
    ##--Generate each honeyword  
    res = []
    errors_occured = 0
    if mode == "honeywords":
    
        tasks = [
            (idx, query, k, start_index, seed + idx, replacement)
            for idx, query in enumerate(queries)
        ]

        with multiprocessing.Pool(initializer=_init_worker, initargs=(pcfg,)) as pool:
            results = tqdm(
                pool.imap(_generate_honeywords_for_single_password, tasks),
                total=len(tasks),
                desc="Generating Honeywords"
            )
            
            for honeyword_run, local_errors in results:
                res.append(honeyword_run)
                errors_occured += local_errors
    else:
        
        tasks = [
            (idx, start_index)
            for idx in range(k)
        ]
        
        with multiprocessing.Pool(initializer=_init_worker, initargs=(pcfg,)) as pool:
            results = tqdm(
                pool.imap(_generate_password, tasks),
                total=k,
                desc="Generating Honeywords"
            )
            
            for password, local_errors in results:
                res.append(password)
                errors_occured += local_errors
    
    if errors_occured != 0:
        print()
        if errors_occured == 1:
            print("Warning: " + str(errors_occured) + " error occured when trying to generate your honeywords")
        else:
            print("Warning: " + str(errors_occured) + " errors occured when trying to generate your honeywords")
            
        print("This is usually caused by your terminal not supporting the character encoding of a specific honeyword")
        print("For example, the honeyword may have contained a letter in a language your terminal doesn't support")
   
    return res