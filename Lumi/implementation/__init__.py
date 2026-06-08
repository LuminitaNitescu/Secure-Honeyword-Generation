"""
honeywords — implementation of Akshima et al. (IEEE TDSC 2019).

Submodules
----------
levenshtein        Edit-distance computation (typo-safety).
policy             Password policy enforcement (Section 5.1).
tokenizer          Token / pattern utilities shared by all models.
frequency_db       FreqIndex, FrequencyDatabase, preset corpus (Algorithm 1).
honeychecker       Honeychecker, HoneyEntry, SweetwordList.
model_evolving     Evolving-password model (Algorithm 2, Section 5.3.1a).
model_user_profile User-profile model (Section 5.3.1b).
model_append_secret Append-secret model + authentication (Section 5.3.2a).
"""