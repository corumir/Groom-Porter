import re
import os
import yara
import collections

class yaraparse():
	
	def __init__(self, yarafile):
		self.path = yarafile
		self.text = self.get_text()
		self.imports = []
		self.rules = {
				'rulename': [],
				'imports': [],
				'global': [],
				'private': [],
				'tags': [],
				'metadata': [],
				'strings': [],
				'condition': [],
				'index': []
			}
	
	def __str__(self):
		if not self.rules['rulename']:
			return "No diagnostics on %s" % self.path
		else:
			str_return = ["\nFilename: %s" % self.path]
			str_return.append("Total Rules: %d" % len(self.rules['rulename']))
			str_return.append("Global: %d" % self.rules['global'].count(True))
			str_return.append("Private: %d" % self.rules['private'].count(True))
			
			#set variables
			import_count = {
				'pe': 0,
				'elf': 0,
				'cuckoo': 0,
				'magic': 0,
				'hash': 0,
				'math': 0,
			}
			str_total = []
			type_count = {
				'text': 0,
				'hex': 0,
				'regex': 0
			}
			mod_count = {
				'nocase': 0,
				'fullword': 0,
				'ascii': 0,
				'wide': 0
			}
			c_count = {
				'and': 0,
				'or': 0,
				'#': 0,
				'@': 0,
				'!': 0,
				'at': 0,
				'in': 0,
				'filesize': 0,
				'entrypoint': 0,
				'int': 0,
				'uint': 0,
				'of': 0,
				'for': 0,
			}
			c_regex = {
				'and': re.compile(r'\sand\s'),
				'or': re.compile(r'\sor\s'),
				'#': re.compile(r'\#'),
				'@': re.compile(r'\@'),
				'!': re.compile(r'\!'),
				'at': re.compile(r'\sat\s'),
				'in': re.compile(r'\sin\s'),
				'filesize': re.compile(r'filesize(?<![$#!])'),
				'entrypoint': re.compile(r'entrypoint'),
				'int': re.compile(r'int[0-9]+\(.*\)\s*=='),
				'uint': re.compile(r'uint[0-9]+\(.*\)\s*=='),
				'of': re.compile(r'\sof\s'),
				'for': re.compile(r'\sfor\s')
			}
			rule_total = []
			for i in range(len(self.rules['strings'])):
				
				#tally imports
				if 'pe' in self.rules['imports'][i]:
					import_count['pe'] += 1
				if 'elf' in self.rules['imports'][i]:
					import_count['elf'] += 1
				if 'cuckoo' in self.rules['imports'][i]:
					import_count['cuckoo'] += 1
				if 'magic' in self.rules['imports'][i]:
					import_count['magic'] += 1
				if 'hash' in self.rules['imports'][i]:
					import_count['hash'] += 1
				if 'math' in self.rules['imports'][i]:
					import_count['math'] += 1

				#Gather String data
				if self.rules['strings'][i]:
					for string in self.rules['strings'][i]:
						if string['type'] == 'text':
							type_count['text'] += 1
						elif string['type'] == 'hex':
							type_count['hex'] += 1
						elif string['type'] == 'regex':
							type_count['regex'] += 1
						if string['modifiers']:
							#string 'A' w/ modifiers is different than string 'A'
							str_total.append('%s %s' % (string['string'], ' '.join(string['modifiers'])))
							for mod in string['modifiers']:
								if mod == 'nocase':
									mod_count['nocase'] += 1
								elif mod == 'fullword':
									mod_count['fullword'] += 1
								elif mod == 'ascii':
									mod_count['ascii'] += 1
								elif mod == 'wide':
									mod_count['wide'] += 1
						else:
							str_total.append(string['string'])
				
				else:
					pass
				
				condition = self.rules['condition'][i]
				c_count['and'] += len(c_regex['and'].findall(condition))
				c_count['or'] += len(c_regex['or'].findall(condition))
				c_count['#'] += len(c_regex['#'].findall(condition))
				c_count['@'] += len(c_regex['@'].findall(condition))
				c_count['!'] += len(c_regex['!'].findall(condition))
				c_count['at'] += len(c_regex['at'].findall(condition))
				c_count['in'] += len(c_regex['in'].findall(condition))
				c_count['filesize'] += len(c_regex['filesize'].findall(condition))
				c_count['entrypoint'] += len(c_regex['entrypoint'].findall(condition))
				c_count['int'] += len(c_regex['int'].findall(condition))
				c_count['uint'] += len(c_regex['uint'].findall(condition))
				c_count['of'] += len(c_regex['of'].findall(condition))
				c_count['for'] += len(c_regex['for'].findall(condition))
			
			#Import print section
			str_return.append("Imports: %s-%s, %s-%s, %s-%s, %s-%s, %s-%s, %s-%s" % (
				'pe', import_count['pe'],
				'elf', import_count['elf'],
				'cuckoo', import_count['cuckoo'],
				'magic', import_count['magic'],
				'hash', import_count['hash'],
				'math', import_count['math']))
			
			#String print section
			str_counter = collections.Counter(str_total)
			str_return.append("\nTotal Strings: %d" % len(str_total))
			str_return.append("Type Count: text-%d, hex-%d, regex-%d " % (type_count['text'], type_count['hex'], type_count['regex']))
			str_return.append("Mod Count: nocase-%d, fullword-%d, ascii-%d, wide-%d" % (mod_count['nocase'], mod_count['fullword'], mod_count['ascii'], mod_count['wide']))
			str_return.append("Unique Strings: %d " % len(str_counter.keys()))
			str_return.append("Top 20 strings:")
			for pair in str_counter.most_common(20):
				str_return.append("%s: %d" % (pair[0], pair[1]))
			
			#Condtion print section
			str_return.append('\nCondition stats:')
			if c_count['and'] > 0:
				str_return.append('and: %d' % c_count['and'])
			if c_count['or'] > 0:
				str_return.append('or: %d' % c_count['or'])
			if c_count['#'] > 0:
				str_return.append('#: %d' % c_count['#'])
			if c_count['@'] > 0:
				str_return.append('@: %d' % c_count['@'])
			if c_count['!'] > 0:
				str_return.append('!: %d' % c_count['!'])
			if c_count['at'] > 0:
				str_return.append('at: %d' % c_count['at'])
			if c_count['in'] > 0:
				str_return.append('in: %d' % c_count['in'])
			if c_count['filesize'] > 0:
				str_return.append('filesize: %d' % c_count['filesize'])
			if c_count['entrypoint'] > 0:
				str_return.append('entrypoint: %d' % c_count['entrypoint'])
			if c_count['int'] > 0:
				str_return.append('int: %d' % c_count['int'])
			if c_count['uint'] > 0:
				str_return.append('uint: %d' % c_count['uint'])
			if c_count['of'] > 0:
				str_return.append('of: %d' % c_count['of'])
			if c_count['for'] > 0:
				str_return.append('for: %d' % c_count['for'])
			
			return '\n'.join(str_return)
				
	def get_text(self):
		with open(self.path, 'r') as f:
			text = f.read()
		f.close()
		return text
	
	def get_line(self, rule_num):
		index = self.rules['index'][rule_num]
		lines = [n.start() for n in re.finditer(r'\n', self.text)]
		lines.insert(0, 0)
		for i in range(len(lines)):
			if lines[i] <= index < lines[i+1]:
				return i+1 #line count starts from 1
		
	def compile_check(self):
		try:
			yara.compile(self.path)
			return True, None
		except yara.SyntaxError, why:
			return False, why	
			
	def parse(self):
		self.lines = [n.start() for n in re.finditer(r'\n', self.text)]
		self.lines.insert(0, 0)
		
		re_imports = re.compile(r'(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(import\s*\"(pe|elf|cuckoo|magic|hash|math)\")')
		re_rule = re.compile(r'(?:\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(?:\/(?:\\.|[^\/\\])*\/)|(global|private|rule.*?{)|(meta\s*:)|(strings\s*:)|(condition\s*:)', re.DOTALL | re.MULTILINE)
		re_meta = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(\w*\s*=)|(true|false)|([0-9])', re.DOTALL)
		re_string = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(?:\/\*.*?\*\/|(?<!\\)\/\/[^\r\n]*)|(nocase|fullword|ascii|wide)|({[A-Fa-f0-9\(\)\s\|\[\]\-]*})|(\/.*\/)|(\$\w*\s*=\s*)', re.DOTALL)
		
		#find all imports
		imp_matches = [n for n in re_imports.finditer(self.text)]
		imports = []
		for imp_match in imp_matches:
			if imp_match.group(1):
				if not (imp_match.group(2) in imports):
					imports.append(imp_match.group(2))
		
		self.imports = imports
		
		#match rules
		match = [n for n in re_rule.finditer(self.text)]

		# parse out global, private, rulename, tags, meta, strings, conditions
		rules = []
		meta = []
		string = []
		condition = []
		G = False # Global
		P = False # Private
		for i in range(len(match)):
			if match[i].group(1): # global, private, rulename, tags
				if match[i].group(1) == 'global':
					G = True
				elif match[i].group(1) == 'private':
					P = True
				else:
					rule_index = match[i].start(1)
					rule_split = match[i].group(1).split(':')
					if len(rule_split) > 1:
						tags = rule_split[-1].replace('{', '').split()
					else:
						tags = []
					rulename = rule_split[0].replace('{', '').split()[-1]
					
			if match[i].group(2): # meta
				start_index = match[i].end(2)
				n = 1
				try:
					while not(match[i+n].group(3) or match[i+n].group(4)):
						n += 1
					end_index = match[i+n].start(0)
					meta_matches = [n for n in re_meta.finditer(self.text, start_index, end_index)]

					for meta_match in meta_matches:
						if meta_match.group(2):
							meta_name = meta_match.group(2).replace('=', '').rstrip()
						else:
							meta_content = meta_match.group(0)
							meta.append({'name': meta_name, 'content': meta_content})
					
				except IndexError:
					continue
				
			if match[i].group(3): # strings
				start_index = match[i].end(3)
				n = 1
				try:
					while not(match[i+n].group(4)):
						n += 1
					end_index = match[i+n].start(0)
					string_match = [n for n in re_string.finditer(self.text, start_index, end_index)]

					for ii in range(len(string_match)):
						modifiers = []
						if string_match[ii].group(5): # name
							string_name = string_match[ii].group(5).replace('=', '').rstrip()
						elif string_match[ii].group(1): # text string
							string_type = 'text'
							string_content = string_match[ii].group(1)
							m = 1
							while string_match[ii+m].group(2):
								modifiers.append(string_match[ii+m].group(2))
								m += 1
								if (ii+m) >= len(string_match):
									break
							string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
						elif string_match[ii].group(3): # hex string
							string_type = 'hex'
							string_content = string_match[ii].group(3)
							string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
						elif string_match[ii].group(4): # regex string
							string_type = 'regex'
							string_content = string_match[ii].group(4)
							string.append({'name': string_name, 'string': string_content, 'type': string_type, 'modifiers': modifiers})
				
				except IndexError:
					continue

			if match[i].group(4): # condition
				start_index = match[i].end(4)
				n = 1
				try:
					while not(match[i+n].group(1)):
						n += 1
					end_index = match[i+n].start(0)
					condition = self.text[start_index:end_index].replace('}', '').strip()

				except IndexError:
					condition = self.text[start_index:].replace('}', '').strip()
				
				self.rules['rulename'].append(rulename)
				self.rules['imports'].append([imp for imp in self.imports if imp+'.' in condition])
				self.rules['global'].append(G)
				self.rules['private'].append(P)
				self.rules['tags'].append(tags)
				self.rules['metadata'].append(meta)
				self.rules['strings'].append(string)
				self.rules['condition'].append(condition)
				self.rules['index'].append(rule_index)
				
				G = False
				P = False
				meta = []
				string = []
		
		return None

