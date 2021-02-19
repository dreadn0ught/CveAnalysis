# CveAnalysis
Library to analyse CVEs and CWEs easily, this is just some basic code at the moment but plan to flesh it out

## CWE
The CWE class contains the CWE database converted from XML to JSON for easier analysis. A sample CWE entry looks like
this:

{'@Abstraction': 'Base',
 '@ID': '1243',
 '@Name': 'Sensitive Non-Volatile Information Not Protected During Debug',
 '@Status': 'Incomplete',
 '@Structure': 'Simple',
 'Applicable_Platforms': {'Architecture': {'@Class': 'Architecture-Independent',
                                           '@Prevalence': 'Undetermined'},
                          'Language': {'@Class': 'Language-Independent',
                                       '@Prevalence': 'Undetermined'},
                          'Operating_System': {'@Class': 'OS-Independent',
                                               '@Prevalence': 'Undetermined'},
                          'Technology': {'@Class': 'Technology-Independent',
                                         '@Prevalence': 'Undetermined'}},
 'Common_Consequences': {'Consequence': {'Impact': ['Modify Memory',
                                                    'Bypass Protection '
                                                    'Mechanism'],
                                         'Scope': ['Confidentiality',
                                                   'Access Control']}},
 'Content_History': {'Modification': [{'Modification_Comment': 'updated '
                                                               'Relationships',
                                       'Modification_Date': '2020-06-25',
                                       'Modification_Name': 'CWE Content Team',
                                       'Modification_Organization': 'MITRE'},
                                      {'Modification_Comment': 'updated '
                                                               'Applicable_Platforms, '
                                                               'Demonstrative_Examples, '
                                                               'Description, '
                                                               'Name, '
                                                               'Potential_Mitigations, '
                                                               'Related_Attack_Patterns',
                                       'Modification_Date': '2020-08-20',
                                       'Modification_Name': 'CWE Content Team',
                                       'Modification_Organization': 'MITRE'}],
                     'Previous_Entry_Name': {'#text': 'Exposure of '
                                                      'Security-Sensitive Fuse '
                                                      'Values During Debug',
                                             '@Date': '2020-08-20'},
                     'Submission': {'Submission_Date': '2020-02-12',
                                    'Submission_Name': 'Arun Kanuparthi, '
                                                       'Hareesh Khattri, '
                                                       'Parbati Kumar Manna, '
                                                       'Narasimha Kumar V '
                                                       'Mangipudi',
                                    'Submission_Organization': 'Intel '
                                                               'Corporation'}},
 'Demonstrative_Examples': {'Demonstrative_Example': {'Example_Code': [{'@Language': 'Other',
                                                                        '@Nature': 'bad',
                                                                        'xhtml:div': 'All '
                                                                                     'microarchitectural '
                                                                                     'registers '
                                                                                     'in '
                                                                                     'this '
                                                                                     'chip '
                                                                                     'can '
                                                                                     'be '
                                                                                     'accessed '
                                                                                     'through '
                                                                                     'the '
                                                                                     'debug '
                                                                                     'interface. '
                                                                                     'As '
                                                                                     'a '
                                                                                     'result, '
                                                                                     'even '
                                                                                     'an '
                                                                                     'untrusted '
                                                                                     'debugger '
                                                                                     'can '
                                                                                     'access '
                                                                                     'this '
                                                                                     'data '
                                                                                     'and '
                                                                                     'retrieve '
                                                                                     'sensitive '
                                                                                     'manufacturing '
                                                                                     'data.'},
                                                                       {'@Nature': 'informative',
                                                                        'xhtml:div': 'Registers '
                                                                                     'used '
                                                                                     'to '
                                                                                     'store '
                                                                                     'sensitive '
                                                                                     'values '
                                                                                     'read '
                                                                                     'from '
                                                                                     'fuses '
                                                                                     'should '
                                                                                     'be '
                                                                                     'blocked '
                                                                                     'during '
                                                                                     'debug. '
                                                                                     'These '
                                                                                     'registers '
                                                                                     'should '
                                                                                     'be '
                                                                                     'disconnected '
                                                                                     'from '
                                                                                     'the '
                                                                                     'debug '
                                                                                     'interface.'}],
                                                      'Intro_Text': 'Sensitive '
                                                                    'manufacturing '
                                                                    'data '
                                                                    '(such as '
                                                                    'die '
                                                                    'information) '
                                                                    'are '
                                                                    'stored in '
                                                                    'fuses. '
                                                                    'When the '
                                                                    'chip '
                                                                    'powers '
                                                                    'on, these '
                                                                    'values '
                                                                    'are read '
                                                                    'from the '
                                                                    'fuses and '
                                                                    'stored in '
                                                                    'microarchitectural '
                                                                    'registers. '
                                                                    'These '
                                                                    'registers '
                                                                    'are only '
                                                                    'given '
                                                                    'read '
                                                                    'access to '
                                                                    'trusted '
                                                                    'software '
                                                                    'running '
                                                                    'on the '
                                                                    'core. '
                                                                    'Untrusted '
                                                                    'software '
                                                                    'running '
                                                                    'on the '
                                                                    'core is '
                                                                    'not '
                                                                    'allowed '
                                                                    'to access '
                                                                    'these '
                                                                    'registers.'}},
 'Description': 'Access to security-sensitive information stored in fuses is '
                'not limited during debug.',
 'Extended_Description': {'xhtml:p': 'Several security-sensitive values are '
                                     'are programmed into fuses to be used '
                                     'during early-boot flows or later at '
                                     'runtime. Examples of these '
                                     'security-sensitive values include root '
                                     'keys, encryption keys, '
                                     'manufacturing-specific information, '
                                     'chip-manufacturer-specific information, '
                                     'and original-equipment-manufacturer '
                                     '(OEM) data. After the chip is powered '
                                     'on, these values are sensed from fuses '
                                     'and stored in temporary locations such '
                                     'as registers and local memories. These '
                                     'locations are typically access-control '
                                     'protected from untrusted agents capable '
                                     'of accessing them. Even to trusted '
                                     'agents, only read-access is provided. '
                                     'However, these locations are not blocked '
                                     'during debug operations, allowing a '
                                     'users to access this sensitive '
                                     'information.'},
 'Modes_Of_Introduction': {'Introduction': [{'Phase': 'Architecture and '
                                                      'Design'},
                                            {'Phase': 'Implementation'}]},
 'Potential_Mitigations': {'Mitigation': {'Description': {'xhtml:p': 'Disable '
                                                                     'access '
                                                                     'to '
                                                                     'security-sensitive '
                                                                     'information '
                                                                     'stored '
                                                                     'in fuses '
                                                                     'directly '
                                                                     'and also '
                                                                     'reflected '
                                                                     'from  '
                                                                     'temporary '
                                                                     'storage '
                                                                     'locations '
                                                                     'when in '
                                                                     'debug '
                                                                     'mode.'},
                                          'Phase': ['Architecture and Design',
                                                    'Implementation']}},
 'Related_Attack_Patterns': {'Related_Attack_Pattern': [{'@CAPEC_ID': '116'},
                                                        {'@CAPEC_ID': '545'}]},
 'Related_Weaknesses': {'Related_Weakness': {'@CWE_ID': '200',
                                             '@Nature': 'ChildOf',
                                             '@Ordinal': 'Primary',
                                             '@View_ID': '1000'}}}

## TODO
1. Create way to pull in OWASP top 10
2. Create way to get all parents
3. Come up with own process to classify major vulnerabilities (based on my list)
3a. Test this to make sure you don't have accidental overlap of CWES between groups
3b. Identify CWEs you've missed and see what they are
4. Create stats for each vulnerability group

5.  Map CVEs based on affected technology?
6.  Create JSON reports based on first desired reports
6a. OWASP coverage
6b. Most prevalent "vulnerability"
6c. Most dangerous vulnerabilities

7.  Create easy way to score CVEs and CWEs based on prevalence vs severity
