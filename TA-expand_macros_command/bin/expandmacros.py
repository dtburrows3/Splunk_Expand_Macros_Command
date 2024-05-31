#!/usr/bin/env python

import os,sys,re,json,csv
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators, GeneratingCommand



def get_all_splunk_macros(response_payload):
    macro_array = []
    comma_matcher = re.compile(r",(?=(?:[^\"']*[\"'][^\"']*[\"'])*[^\"']*$)")
    for entry in response_payload['entry']:
        try:
            macro_dict = {}
            macro_dict['disabled'] = entry['content']['disabled']
            macro_dict['permissions'] = entry['acl']['sharing']
            macro_dict['splunk_app'] = entry['content']['eai:appName']
            macro_dict['name'] = entry['name']
            macro_dict['definition'] = entry['content']['definition'].replace('\n', ' ')
            if 'args' in entry['content'].keys():
                macro_dict['args'] = [ '{}'.format(x).strip(" ") for x in comma_matcher.split(entry['content']['args']) ]
            if len(re.findall(r'(?<!\`{2})\`[^\`]+\`(?!\`{2})', macro_dict['definition'])) > 0:
                macro_dict['nested_macros'] = [ '{}'.format(x).strip("`") for x in re.findall(r'(?<!\`{2})\`[^\`]+\`(?!\`{2})', macro_dict['definition']) ]
            macro_array.append(macro_dict)
        except:
            print("Unable to Add macro to list")
    return macro_array

def check_macro_input_for_designated_token_assignments(parsed_args: list) -> list:
    replaced_macros_args_parsed = []
    arg_number = 0
    if all(bool(re.search("=", entry)) for entry in parsed_args):
        for arg in parsed_args:
            arg_number += 1
            replaced_arg = arg.replace('"', '')
            key = replaced_arg.split('=')[0]
            value = replaced_arg.split('=')[1]
            kv_arg = {
                'number': arg_number,
                'token': key,
                'value': value
            }
            replaced_macros_args_parsed.append(kv_arg)
    else:
        for arg in parsed_args:
            arg_number += 1
            value = arg
            kv_arg = {
                'number': arg_number,
                'value': value
            }
            replaced_macros_args_parsed.append(kv_arg)
    return replaced_macros_args_parsed

def parse_use_macros(used_macros):
    used_macro_array = []
    comma_matcher = re.compile(r",(?=(?:[^\"']*[\"'][^\"']*[\"'])*[^\"']*$)")
    for used_macro in used_macros:
        used_macro_dict = {}
        if re.search(r'[a-zA-Z0-9\-\_]+\(([^\)]+)\)', used_macro):
            used_macro_args_string = re.search(r'[a-zA-Z0-9\-\_]+\(([^\)]+)\)', used_macro).group(1)
            used_macro_args_parsed = [ '{}'.format(x).strip(' ').strip('"') for x in comma_matcher.split(used_macro_args_string) ]
            used_macro_args_count = len(used_macro_args_parsed)
            used_macro_dict['raw'] = '`' + used_macro + '`'
            used_macro_dict['name'] = re.search(r'([a-zA-Z0-9\-\_]+)\([^\)]+\)', used_macro).group(1) + '(' + str(used_macro_args_count) + ')'
            #used_macro_dict['args'] = used_macro_args_parsed
            used_macro_dict['args'] = check_macro_input_for_designated_token_assignments(used_macro_args_parsed)
            used_macro_dict['arg_count'] = used_macro_args_count
        else:
            used_macro_dict['raw'] = '`' + used_macro + '`'
            used_macro_dict['name'] = used_macro
            used_macro_dict['arg_count'] = 0
        used_macro_array.append(used_macro_dict)
    return used_macro_array

def gather_used_macros(spl):
    used_macros = [ '{}'.format(x).strip("`") for x in re.findall(r'(?<!\`{2})\`[^\`]+\`(?!\`{2})', spl) ]
    return used_macros

def map_used_macros_input_tokens(used_macro_array, macro_array):
    mapped_used_macro_array = []
    for used_macro_dict in used_macro_array:
        for macro_dict in macro_array:
            if used_macro_dict['name'] == macro_dict['name']:
                try:
                    used_macro_dict['definition'] = macro_dict['definition']
                    if used_macro_dict['arg_count'] > 0:
                        arg_mapping_array = []
                        for i in range(len(macro_dict['args'])):
                            if not 'token' in used_macro_dict['args'][i].keys():
                                arg_mapping_dict = {}
                                arg_mapping_dict['token'] = macro_dict['args'][i]
                                arg_mapping_dict['used'] = used_macro_dict['args'][i]['value']
                                arg_mapping_array.append(arg_mapping_dict)
                            else:
                                arg_mapping_dict = {}
                                arg_mapping_dict['token'] = used_macro_dict['args'][i]['token']
                                arg_mapping_dict['used'] = used_macro_dict['args'][i]['value']
                                arg_mapping_array.append(arg_mapping_dict)
                        used_macro_dict['arg_mapping'] = arg_mapping_array
                except:
                    continue
        mapped_used_macro_array.append(used_macro_dict)
    curated_mapped_used_macro_array = []
    for mapped_used_macro_dict in mapped_used_macro_array:
        if 'definition' not in mapped_used_macro_dict.keys():
            mapped_used_macro_dict['definition'] = '#Unfound!# ' + mapped_used_macro_dict['name'] + ' #!Unfound#'
        curated_mapped_used_macro_array.append(mapped_used_macro_dict)
    return curated_mapped_used_macro_array

def replace_used_macros_definition_tokens(mapped_used_macro_array):
    replaced_mapped_used_macro_array = []
    for mapped_used_macro_dict in mapped_used_macro_array:
        tmp_replacement_spl = mapped_used_macro_dict['definition']
        if 'arg_mapping' in mapped_used_macro_dict.keys():
            for mapped_arg_dict in mapped_used_macro_dict['arg_mapping']:
                token_pattern = mapped_arg_dict['token']
                tmp_replacement_spl = re.sub(rf'\${token_pattern}\$', mapped_arg_dict['used'], tmp_replacement_spl)
        mapped_used_macro_dict['replaced_definition'] = tmp_replacement_spl
        replaced_mapped_used_macro_array.append(mapped_used_macro_dict)
    return replaced_mapped_used_macro_array

def substitute_used_macro_tokens_with_inputs_args(original_spl, replaced_mapped_used_macro_array):
    output_spl = original_spl
    for replaced_mapped_used_macro in replaced_mapped_used_macro_array:
        output_spl = output_spl.replace(replaced_mapped_used_macro['raw'], replaced_mapped_used_macro['replaced_definition'])
    return output_spl




@Configuration()
class ExpandMacros(StreamingCommand):

    input_field = Option(require=True, validate=validators.Fieldname())
    output_field = Option(require=False, default='expanded_spl')

    def stream(self, records):

        input_field = self.input_field
        output_field = self.output_field


        # Session key - need for authentication in post

        session_key = self._metadata.searchinfo.session_key
        auth = 'Splunk ' + session_key
        headers = {'Authorization': auth}
        params = {'count': 0}
        response_format = {'output_mode': 'json'}
        user_context = '-'
        app_context = '-'
        
        s = requests.Session()
        response = s.get('https://localhost:8089/servicesNS/' + user_context + '/' + app_context + '/configs/conf-macros', headers=headers, params=params, data=response_format, verify=False)
        response_payload = json.loads(response.text)
        
        
        all_splunk_macros = get_all_splunk_macros(response_payload)
        
        for index, record in enumerate(records):
            spl = record[input_field]
            
            while len(gather_used_macros(spl)) > 0:
                raw_used_macros = gather_used_macros(spl)
                parsed_used_macros = parse_use_macros(raw_used_macros)
                arg_mapped_used_macros = map_used_macros_input_tokens(parsed_used_macros, all_splunk_macros)
                replaced_used_macros = replace_used_macros_definition_tokens(arg_mapped_used_macros)
                spl = substitute_used_macro_tokens_with_inputs_args(spl, replaced_used_macros)
            output_spl = spl
            
            output_spl = spl
            self.add_field(record, output_field, output_spl)

            yield record

dispatch(ExpandMacros, sys.argv, sys.stdin, sys.stdout, __name__)
