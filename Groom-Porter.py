#------------------------------------
#--------import error check----------
import re
import sys
import codecs
import itertools

error_list = []
try:
	import yara
except ImportError:
	error_list.append('Error on import yara: goto yara.readthedocs.io for installation instructions')
if len(error_list) > 0:
	print '\n'.join(error_list)
	exit()
#--------import error check----------
#------------------------------------

class yararule:
	def __init__(self, name):
		self.name = name
		self.ruletype = []
		self.tags = []
		self.strings = []
		self.condition = ''
		
	def __str__(self):
		str_return = ['name: %s' % self.name]
		
		if len(self.ruletype) == 0:
			type_return = 'ruletype: none'
		else:
			type_return = 'ruletype: ' + ', '.join(self.ruletype)
		str_return.append(type_return)
		
		if len(self.tags) == 0:
			tags_return = 'tags: none'
		else:
			tags_return = 'tags: ' + ', '.join(self.tags)
		str_return.append(tags_return)

		if len(self.strings) == 0:
			strings_return = 'strings: none'
		else:
			strings_return = 'strings: ' + ', '.join(self.strings)
		str_return.append(strings_return)

		if self.condition == '':
			condition_return = 'condition: none'
		else:
			condition_return = 'condition: %s' % self.condition
		str_return.append(condition_return)
		
		return '\n'.join(str_return)

class U_yararule:
	
	def __init__(self, ID):
		self.ID = ID
		self.name = []
		self.ruletype = []
		self.tags = []
		self.line = []
		self.strings = []
		self.condition = ''
	
	def __str__(self):
		str_return = ['ID: %s' % self.ID, 'name: %s' % self.name]
		
		if len(self.ruletype) == 0:
			type_return = 'ruletype: none'
		else:
			type_return = 'ruletype: ' + ', '.join(self.ruletype)
		str_return.append(type_return)
		
		if len(self.tags) == 0:
			tags_return = 'tags: none'
		else:
			tags_return = 'tags: ' + ', '.join(self.tags)
		str_return.append(tags_return)

		if len(self.line) == 0:
			line_return = 'line: none'
		else:
			line_return = 'line: ' + ', '.join(self.line)
		str_return.append(line_return)
		
		if len(self.strings) == 0:
			strings_return = 'strings: none'
		else:
			strings_return = 'strings: ' + ', '.join(self.strings)
		str_return.append(strings_return)

		if self.condition == '':
			condition_return = 'condition: none'
		else:
			condition_return = 'condition: %s' % self.condition
		str_return.append(condition_return)
		
		return '\n'.join(str_return)
	
	def importrule(self, rule):
		self.ruletype.extend(rule.ruletype)
		self.tags.extend(rule.tags)
		
class yarastring:
	def __init__(self, string):
		self.string = string
		self.string_type = ''
		self.keyword = []

	def __str__(self):
		str_return = ['string: %s' % self.string, 'string type: %s' % self.string_type]
		
		if len(self.keyword) == 0:
			key_return = 'keyword: none'
		else:
			key_return = 'keyword: ' + ', '.join(self.keyword)
		str_return.append(key_return)
		
		return '\n'.join(str_return)

class U_yarastring:
	def __init__(self, ID):
		self.ID = ID
		self.string = ''
		self.string_type = ''
		self.keyword = []
		self.line = []
		self.rule = []
		
	def __str__(self):
		str_return = ['ID: %s' % self.ID, 'string: %s' % self.string, 'string type: %s' % self.string_type]
		
		if len(self.keyword) == 0:
			key_return = 'keyword: none'
		else:
			key_return = 'keyword: ' + ', '.join(self.keyword)
		str_return.append(key_return)
		
		if len(self.line) == 0:
			line_return = 'line: none'
		else:
			line_return = 'line: ' + ', '.join(self.line)
		str_return.append(line_return)
		
		if len(self.rule) == 0:
			rule_return = 'rule: none'
		else:
			rule_return = 'rule: ' + ', '.join(self.rule)
		str_return.append(rule_return)
		
		return '\n'.join(str_return)

	def importstring(self, string):
		self.string = string.string
		self.string_type = string.string_type
		self.keyword = string.keyword
	
class yaracondition:
	def __init__(self, condition):
		self.condition = condition
		self.stats = {
		'and': 0, 'or': 0, '#': 0, '@': 0, '!': 0, 
		'at': 0, 'in': 0, 'filesize': 0, 'entrypoint': 0,
		'int': 0, 'uint': 0, 'of': 0, 'for': 0
		}
		
	def __str__(self):
		str_return = ['condition: %s' % self.condition]
		
		str_return.append('stats:')
		str_return.append('\tand: %d' % self.stats['and'])
		str_return.append('\tor: %d' % self.stats['or'])
		str_return.append('\t#: %d' % self.stats['#'])
		str_return.append('\t@: %d' % self.stats['@'])
		str_return.append('\t!: %d' % self.stats['!'])
		str_return.append('\tat: %d' % self.stats['at'])
		str_return.append('\tin: %d' % self.stats['in'])
		str_return.append('\tfilesize: %d' % self.stats['filesize'])
		str_return.append('\tentrypoint: %d' % self.stats['entrypoint'])
		str_return.append('\tint: %d' % self.stats['int'])
		str_return.append('\tuint: %d' % self.stats['uint'])
		str_return.append('\tof: %d' % self.stats['of'])
		str_return.append('\tfor: %d' % self.stats['for'])
		
		return '\n'.join(str_return)

class U_yaracondition:
	def __init__(self, ID):
		self.ID = ID
		self.condition = ''
		self.stringref = []
		self.line = []
		self.rule = []
		self.ruleref = []
		self.stats = {
		'and': 0, 'or': 0, '#': 0, '@': 0, '!': 0, 
		'at': 0, 'in': 0, 'filesize': 0, 'entrypoint': 0,
		'int': 0, 'uint': 0, 'of': 0, 'for': 0
		}
		
	def __str__(self):
		str_return = ['ID: %s' % self.ID,'condition: %s' % self.condition]
		
		if len(self.stringref) == 0:
			stringref_return = 'stringref: none'
		else:
			stringref_return = 'stringref: ' + ', '.join(self.stringref)
		str_return.append(stringref_return)
		
		if len(self.line) == 0:
			line_return = 'line: none'
		else:
			line_return = 'line: ' + ', '.join(self.line)
		str_return.append(line_return)
		
		if len(self.rule) == 0:
			rule_return = 'rule: none'
		else:
			rule_return = 'rule: ' + ', '.join(self.rule)
		str_return.append(rule_return)
		
		if len(self.ruleref) == 0:
			ruleref_return = 'ruleref: none'
		else:
			ruleref_return = 'ruleref: ' + ', '.join(self.ruleref)
		str_return.append(ruleref_return)
		
		str_return.append('stats:')
		str_return.append('\tand: %d' % self.stats['and'])
		str_return.append('\tor: %d' % self.stats['or'])
		str_return.append('\t#: %d' % self.stats['#'])
		str_return.append('\t@: %d' % self.stats['@'])
		str_return.append('\t!: %d' % self.stats['!'])
		str_return.append('\tat: %d' % self.stats['at'])
		str_return.append('\tin: %d' % self.stats['in'])
		str_return.append('\tfilesize: %d' % self.stats['filesize'])
		str_return.append('\tentrypoint: %d' % self.stats['entrypoint'])
		str_return.append('\tint: %d' % self.stats['int'])
		str_return.append('\tuint: %d' % self.stats['uint'])
		str_return.append('\tof: %d' % self.stats['of'])
		str_return.append('\tfor: %d' % self.stats['for'])
		
		return '\n'.join(str_return)
	
	def importcondition(self, condition):
		self.condition = condition.condition
		self.stats = condition.stats
	
class yarafile:
	def __init__(self, filename):
		self.filename = [filename]
		self.text = []
		self.imports = []
		self.includes = []
		self.rules = {'object': [], 'rule': [], 'line': []}
		self.strings = {'object': [], 'string': [], 'name': [], 'keyword': [], 'line': [], 'rule': []}
		self.conditions = {'object': [], 'condition': [], 'line': [], 'rule': []}
		self.U_rules = []
		self.U_strings = []
		self.U_conditions = []
	
	def __str__(self):
		str_return = ['filename: [0] %s' % self.filename[0]]
		
		#includes
		if len(self.includes) == 0:
			str_return.append('Includes: none')
		else:
			str_return.append('Includes: ')
			for i in range(len(self.includes)):
				str_return.append('\t[%d] %s' % (i+1, self.includes[i]))

		#imports
		if len(self.imports) == 0:
			import_return = 'none'
		else:
			import_return = ', '.join(self.imports)

		str_return.append('Imports: %s' % import_return)

		#private & global count
		private_count = 0
		global_count = 0
		for rule in self.rules['object']:
			if 'private' in rule.ruletype:
				private_count += 1
			if 'global' in rule.ruletype:
				global_count += 1

		str_return.extend(['\nTotal Rules: %d (Private: %d, Global: %d)' % (len(self.rules['rule']), private_count, global_count), \
		'Duplicate Rules: %d' % (len(self.rules['rule'])-len(self.U_rules))])
		for rule in self.U_rules:
			if len(rule.line) > 1:
				str_return.append('names: %s; lines: %s' % (', '.join(rule.name), ', '.join(rule.line)))

		str_return.extend(['\nTotal Strings: %d' % len(self.strings['string']), 'Duplicate Strings: %d' % (len(self.strings['string'])-len(self.U_strings))])
		#loop through strings
		string_count = {'string' : [], 'count': [], 'keyword': [], 'line': []}
		keyword_count = {'keyword': [], 'count': []}
		string_type_count = {'text': 0, 'hex' : 0, 'regex': 0}
		for string in self.U_strings:
			string_count['string'].append(string)
			string_count['count'].append(len(string.line))
			for keyword in string.keyword:
				if not(keyword in keyword_count['keyword']):
					keyword_count['keyword'].append(keyword)
					keyword_count['count'].append(1)
				else:
					keyword_count['count'][keyword_count['keyword'].index(keyword)] += 1
			if string.string_type == 'text':
				string_type_count['text'] += 1
			elif string.string_type == 'hex':
				string_type_count['hex'] += 1
			else:
				string_type_count['regex'] += 1
		
		#top 20 strings
		x = string_count['string']
		y = string_count['count']
		string_sorted = [(x,y) for (y,x) in sorted(zip(y,x), reverse=True) if y>1]
		if len(string_sorted) <= 20:
			for elem in string_sorted:
				if len(elem[0].keyword) == 0:
					keyword_return = 'none'
				else:
					keyword_return = ', '.join(elem[0].keyword)
				str_return.append('%s: %d; keyword(s): %s; lines: %s' % (elem[0].string, elem[1], keyword_return, ', '.join(elem[0].line)))
		else:
			for i in range(20):
				if len(string_sorted[i][0].keyword) == 0:
					keyword_return = 'none'
				else:
					keyword_return = ', '.join(string_sorted[i][0].keyword)
				str_return.append('%s: %d; keyword(s): %s; lines: %s' % (string_sorted[i][0].string, string_sorted[i][1], keyword_return, ', '.join(string_sorted[i][0].line)))
		
		#sorted keyword count
		str_return.append('\nKeyword count: ')
		if len(keyword_count['keyword']) == 0:
			str_return.append('none')
		else:
			x = keyword_count['keyword']
			y = keyword_count['count']
			keyword_sorted = [(x,y) for (y,x) in sorted(zip(y,x), reverse=True)]
			for elem in keyword_sorted:
				str_return.append('%s: %d' % (elem[0], elem[1]))
		
		#string type count
		str_return.extend(['\nString type count:', 'text: %d' % string_type_count['text'], \
		'hex: %d' % string_type_count['hex'], 'regex: %d' % string_type_count['regex']])
		
		#loop through conditions
		stats = {
		'and': 0, 'or': 0, '#': 0, '@': 0, '!': 0, 
		'at': 0, 'in': 0, 'filesize': 0, 'entrypoint': 0,
		'int': 0, 'uint': 0, 'of': 0, 'for': 0
		}
		for condition in self.U_conditions:
			stats['and'] += condition.stats['and']
			stats['or'] += condition.stats['or']
			stats['#'] += condition.stats['#']
			stats['@'] += condition.stats['@']
			stats['!'] += condition.stats['!']
			stats['at'] += condition.stats['at']
			stats['in'] += condition.stats['in']
			stats['filesize'] += condition.stats['filesize']
			stats['entrypoint'] += condition.stats['entrypoint']
			stats['int'] += condition.stats['int']
			stats['uint'] += condition.stats['uint']
			stats['of'] += condition.stats['of']
			stats['for'] += condition.stats['for']
		
		str_return.append('\nCondition stats:')
		if stats['and'] > 0:
			str_return.append('and: %d' % stats['and'])
		if stats['or'] > 0:
			str_return.append('or: %d' % stats['or'])
		if stats['#'] > 0:
			str_return.append('#: %d' % stats['#'])
		if stats['@'] > 0:
			str_return.append('@: %d' % stats['@'])
		if stats['!'] > 0:
			str_return.append('!: %d' % stats['!'])
		if stats['at'] > 0:
			str_return.append('at: %d' % stats['at'])
		if stats['in'] > 0:
			str_return.append('in: %d' % stats['in'])
		if stats['filesize'] > 0:
			str_return.append('filesize: %d' % stats['filesize'])
		if stats['entrypoint'] > 0:
			str_return.append('entrypoint: %d' % stats['entrypoint'])
		if stats['int'] > 0:
			str_return.append('int: %d' % stats['int'])
		if stats['uint'] > 0:
			str_return.append('uint: %d' % stats['uint'])
		if stats['of'] > 0:
			str_return.append('of: %d' % stats['of'])
		if stats['for'] > 0:
			str_return.append('for: %d' % stats['for'])
		
		
		return '\n'.join(str_return)
	
	def read_yara(self, filename):
			with codecs.open(filename, 'r', encoding='utf-8') as f:
				return f.read()
			f.close()

	def nextrule(self, text, start_index, newlines, file_count):
		p = {
		'rule' : [re.compile(r'\W*rule\s*'), re.compile(r'\W+')],
		'global': re.compile(r'\W*global\s+'),
		'private': re.compile(r'\W*private\s+'),
		'tag' : [re.compile(r':\s*'), re.compile(r'\W*{')]
		}
		
		rule_start = p['rule'][0].search(text, start_index)
		
		if rule_start is not None:
			#extract rule name
			rule_end = p['rule'][1].search(text, rule_start.end(0))
			new_rule = yararule(text[rule_start.end(0):rule_end.start(0)])
			end_index = rule_end.end(0) #will hold if no tags
			
			#find line number
			for i in range(len(newlines)-1):
				if newlines[i] <= rule_start.end(0) < newlines[i+1]:
					line = '[%d] %d' % (file_count, i)
					break
			
			#look for 'global' & 'private' identifiers
			global_exist = p['global'].search(text, start_index, rule_start.end(0))
			if global_exist is not None:
				new_rule.ruletype.append('global')
			
			private_exist = p['private'].search(text, start_index, rule_start.end(0))
			if private_exist is not None:
				new_rule.ruletype.append('private')
			
			#assign tags if any
			tag_start = p['tag'][0].search(text, rule_end.start(0))
			tag_end = p['tag'][1].search(text, rule_end.start(0))
			if tag_start.end(0) < tag_end.start(0):
				new_rule.tags = text[tag_start.end(0):tag_end.start(0)].split(' ')
				end_index = tag_end.end(0)#update to after tags
			
			return [new_rule, line, end_index]
		else:
			return [None, start_index, start_index]
		
	def nextstring(self, text, start_index, newlines, file_count):
		string_space = re.compile(r'(strings:)|(condition\s*:.*?})', re.DOTALL)
		string_search = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(nocase|fullword|ascii|wide)|({[A-Fa-f0-9\(\)\s\|\[\]\-]*})|(\/.*\/)|(\$\w*\s*=\s*)')
		comments = re.compile(r'(\"(?:\\.|[^\"\\])*\")|(\/\/.*\n)')
		
		str_out = []
		str_name = []
		line = []
		
		single_comment = [n for n in comments.finditer(text, start_index)]
		for comment in single_comment:
			if comment.group(2) != None:
				text = text.replace(comment.group(2), '\n')
		
		matches = [m for m in string_space.finditer(text, start_index)]

		if matches[0].group(1) != None:
			search_start = matches[0].end(1)
			end_index = matches[1].start(2)
			str_matches = [m for m in string_search.finditer(text, search_start, end_index)]
			
			textstrings = [match for match in str_matches if match.group(1) != None]
			hexstrings = [match for match in str_matches if match.group(3) != None]
			regexstrings = [match for match in str_matches if match.group(4) != None]
			str_name = [match.group(0).split()[0] for match in str_matches if match.group(5) != None]
			
			keywords = []
			for Num, match in enumerate(str_matches):
				if match.group(2) != None:
					check = Num
					while True:
						if str_matches[check].group(2) == None:
							keywords.append((match, str_matches[check]))
							break
						else:
							check -= 1
			
			for textstring in textstrings:
				new_string = yarastring(textstring.group(0))
				new_string.string_type = 'text'
				for keyword in keywords:
					if keyword[1].group(0) == textstring.group(0):
						new_string.keyword.append(keyword[0].group(0))
				for j in range(len(newlines)-1):
					if newlines[j] <= textstring.end(0) < newlines[j+1]:
						line.append('[%d] %d' % (file_count, j))
						break
				str_out.append(new_string)
			
			for hexstring in hexstrings:
				new_string = yarastring(hexstring.group(0))
				new_string.string_type = 'hex'
				for j in range(len(newlines)-1):
					if newlines[j] <= hexstring.end(0) < newlines[j+1]:
						line.append('[%d] %d' % (file_count, j))
						break
				str_out.append(new_string)
			
			for regexstring in regexstrings:
				new_string = yarastring(regexstring.group(0))
				new_string.string_type = 'regex'
				for keyword in keywords:
					if keyword[1].group(0) == regexstring.group(0):
						new_string.keyword.append(keyword[0].group(0))
				for j in range(len(newlines)-1):
					if newlines[j] <= regexstring.end(0) < newlines[j+1]:
						line.append('[%d] %d' % (file_count, j))
						break
				str_out.append(new_string)
		
		else:
			end_index = matches[0].start(2)
				
		return [str_out, str_name, line, end_index]
						
	def nextcondition(self, text, start_index, newlines, file_count):
		p = {'pos': [re.compile(r'condition\s*:\s*'), re.compile(r'\s*}')],
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
		
		#find condition statement start and stop indexes
		cond_str = p['pos'][0].search(text, start_index)
		cond_end = p['pos'][1].search(text, cond_str.end(0))
		end_index = cond_end.end(0)
		
		#condition statement
		condition = text[cond_str.end(0):cond_end.start(0)]
		new_condition = yaracondition(condition) #initialize yaracondition

		#line number for condition
		for j in range(len(newlines)-1):
			if newlines[j] <= cond_str.end(0) < newlines[j+1]:
				line = '[%d] %d' % (file_count, j)
				break
		
		#fill in condition.stats 
		new_condition.stats['and'] = len(p['and'].findall(condition))
		new_condition.stats['or'] = len(p['or'].findall(condition))
		new_condition.stats['#'] = len(p['#'].findall(condition))
		new_condition.stats['@'] = len(p['@'].findall(condition))
		new_condition.stats['!'] = len(p['!'].findall(condition))
		new_condition.stats['at'] = len(p['at'].findall(condition))
		new_condition.stats['in'] = len(p['in'].findall(condition))
		new_condition.stats['filesize'] = len(p['filesize'].findall(condition))
		new_condition.stats['entrypoint'] = len(p['entrypoint'].findall(condition))
		new_condition.stats['int'] = len(p['int'].findall(condition))
		new_condition.stats['uint'] = len(p['uint'].findall(condition))
		new_condition.stats['of'] = len(p['of'].findall(condition))
		new_condition.stats['for'] = len(p['for'].findall(condition))
		
		return [new_condition, line, end_index]
	
	def extract(self):
		
		def matches(lst, element):
			result = []
			offset = -1
			while True:
				try:
					offset = lst.index(element, offset+1)
				except ValueError:
					return result
				result.append(offset)
		
		def getstringID(string, keyword):
			for ii in range(len(self.U_strings)):
				if string == self.U_strings[ii].string and keyword == self.U_strings[ii].keyword:
					return self.U_strings[ii].ID

		#------------------------
		#-----find includes------
		def find_includes(filenames):
			new_filenames = []
			for filename in filenames:
				text = self.read_yara(filename)
				self.text.append(text)
				regex = [re.compile(r'\W*include\s+"'), re.compile(r'".*\.yar"')]
				includes = [m for m in regex[0].finditer(text)]
				if len(includes) > 0:
					for i in includes:
						new_include = regex[1].search(text, i.end(0)).group(0).replace('"', '')
						self.includes.append(new_include)
						new_filenames.append(new_include)
			if len(new_filenames) >= 1:
				find_includes(new_filenames)
			else:
				return
		
		find_includes(self.filename)

		#-----find includes------
		#------------------------
		
		ruleIDcount = itertools.count()
		stringIDcount = itertools.count()
		conditionIDcount = itertools.count()
		file_count = 0
		
		for text in self.text:
			newlines = [n.start() for n in re.finditer(r'\n', text)]
			newlines.insert(0, 0)
			start_index = 0

			#------------------------
			#---remove comments------
			comments = [re.compile(r'/\*.+?\*/', re.DOTALL), re.compile(r'(\"(?:\\.|[^\"\\])*\")|(\/\/.*\n)')]
			multi_comment = [n for n in comments[0].finditer(text, start_index)]
			for comment in multi_comment:
				rep = ['\n']
				for line in newlines:
					if comment.start(0) <= line < comment.end(0):
						rep.append('\n')
				text = text.replace(comment.group(0), ''.join(rep))

			single_comment = [n for n in comments[1].finditer(text, start_index)]
			for comment in single_comment:
				if comment.group(2) != None:
					text = text.replace(comment.group(2), '\n')
			#---remove comments------
			#------------------------

			#------------------------
			#-----find imports-------
			regex = [re.compile(r'\W*import\s+'), re.compile(r'"[a-z]*"')]
			imports = [m for m in regex[0].finditer(text)]
			if len(imports) >= 1:
				for i in imports:
					new_import = regex[1].search(text, i.end(0)).group(0)
					if not(new_import in self.imports):
						self.imports.append(new_import)
			#-----find imports-------
			#------------------------
			
			#Parse Rules, Strings, & Conditions from Yarafile
			while True:
				[new_rule, rule_line, end_index] = self.nextrule(text, start_index, newlines, file_count)
				if new_rule is not None:
					[new_string, str_name, string_line, end_index] = self.nextstring(text, end_index, newlines, file_count)
					for i in range(len(new_string)):
						new_rule.strings.append(new_string[i].string)
						self.strings['object'].append(new_string[i])
						self.strings['string'].append(new_string[i].string)
						self.strings['name'].append(str_name[i])
						self.strings['keyword'].append(new_string[i].keyword)
						self.strings['line'].append(string_line[i])
						self.strings['rule'].append(new_rule.name)
					[new_condition, condition_line, end_index] = self.nextcondition(text, end_index, newlines, file_count)
					new_rule.condition = new_condition.condition
					self.conditions['object'].append(new_condition)
					self.conditions['condition'].append(new_condition.condition)
					self.conditions['line'].append(condition_line)
					self.conditions['rule'].append(new_rule.name)
					self.rules['object'].append(new_rule)
					self.rules['rule'].append(new_rule.name)
					self.rules['line'].append(rule_line)
					
					start_index = end_index
					for j in range(len(newlines)-1):
						if newlines[j] <= start_index < newlines[j+1]:
							print "line %s of %s" % (len(newlines[0:j]), len(newlines))
							break
				else:
					break
			file_count += 1
		#---------------------------------------	
		#----------unique strings---------------
		string_index = range(len(self.strings['string']))
		while len(string_index) >= 1:
			check_strings = [self.strings['string'][i] for i in string_index]
			check_keyword = [self.strings['keyword'][i] for i in string_index]
			dup_strings = matches(check_strings, check_strings[0])
			check_keyword = [check_keyword[i] for i in dup_strings]
			dup_keys = matches(check_keyword, check_keyword[0])
			removes = [dup_strings[i] for i in dup_keys]
			ID = 'S%0.6d' % next(stringIDcount)
			new_Ustring = U_yarastring(ID)
			new_Ustring.importstring(self.strings['object'][string_index[0]])
			for remove in removes:
				index = string_index[remove]
				new_Ustring.line.append(self.strings['line'][index])
				new_Ustring.rule.append(self.strings['rule'][index])
			self.U_strings.append(new_Ustring)
			for remove in sorted(removes, reverse=True):
				del string_index[remove]	
		#----------unique strings---------------
		#---------------------------------------

		#---------------------------------------
		#----------unique conditions------------
		sub_conditions = []
		for i in range(len(self.conditions['condition'])):
			sub_condition = self.conditions['condition'][i]
			for j in range(len(self.strings['string'])):
				if self.conditions['rule'][i] == self.strings['rule'][j]:
					#sub string name with U_string ID
					ID = getstringID(self.strings['string'][j], self.strings['keyword'][j])
					ID_dollar = '$'+ID
					ID_at = '@'+ID
					ID_pound = '#'+ID
					name_dollar = self.strings['name'][j]
					name_at = self.strings['name'][j].replace('$', '@')
					name_pound = self.strings['name'][j].replace('$', '#')
					sub_condition = sub_condition.replace(name_dollar, ID_dollar)
					sub_condition = sub_condition.replace(name_at, ID_at)
					sub_condition = sub_condition.replace(name_pound, ID_pound)
			sub_conditions.append(sub_condition)

		#update condition objects w/ string IDs
		for i in range(len(sub_conditions)):
			self.conditions['object'][i].condition = sub_conditions[i]
		
		#eliminate duplicates
		condition_index = range(len(sub_conditions))
		while len(condition_index) >= 1:
			check_conditions = [sub_conditions[i] for i in condition_index]
			dup_indexes = matches(check_conditions, check_conditions[0])
			ID = 'C%0.6d' % next(conditionIDcount)
			new_Ucondition = U_yaracondition(ID)
			new_Ucondition.importcondition(self.conditions['object'][condition_index[0]])
			for remove in dup_indexes:
				index = condition_index[remove]
				new_Ucondition.line.append(self.conditions['line'][index])
				new_Ucondition.rule.append(self.conditions['rule'][index])
			condstrings = [m.group(0) for m in re.finditer(r'S[0-9]{6}', new_Ucondition.condition)]
			new_Ucondition.stringref.extend(condstrings)
			for rule in self.rules['rule']:
				if rule in new_Ucondition.condition:
					new_Ucondition.ruleref.append(rule)
			self.U_conditions.append(new_Ucondition)
			for remove in sorted(dup_indexes, reverse=True):
				del condition_index[remove]
		#----------unique conditions------------
		#---------------------------------------
		
		#---------------------------------------
		#----------unique rules-----------------
		rule_check = {'rule': [], 'strings': [], 'condition': []}
		for rule in self.rules['rule']:
			string_indexes = [i for i in range(len(self.strings['rule'])) if rule == self.strings['rule'][i]]
			condition = [sub_conditions[i] for i in range(len(self.conditions['rule'])) if rule == self.conditions['rule'][i]]
			stringIDs = [getstringID(self.strings['string'][index], self.strings['keyword'][index]) for index in string_indexes]
			rule_check['rule'].append(rule)
			rule_check['strings'].append(stringIDs)
			rule_check['condition'].append(condition)
		
		rule_index = range(len(rule_check['rule']))
		while len(rule_index) >= 1:
			check_strings = [rule_check['strings'][i] for i in rule_index]
			check_conditions = [rule_check['condition'][i] for i in rule_index]
			dup_conditions = matches(check_conditions, check_conditions[0])
			dup_strings = [j for j in range(len(check_strings)) if set(check_strings[0]) == set(check_strings[j])]
			dup_indexes = list(set(dup_conditions) & set(dup_strings))
			ID = 'R%0.6d' % next(ruleIDcount)
			new_Urule = U_yararule(ID)
			new_Urule.importrule(self.rules['object'][rule_index[0]])
			for remove in dup_indexes:
				index = rule_index[remove]
				new_Urule.line.append(self.rules['line'][index])
				new_Urule.name.append(self.rules['rule'][index])
			new_Urule.strings.extend(check_strings[0])
			new_Urule.condition = check_conditions[0][0]
			self.U_rules.append(new_Urule)
			for remove in sorted(dup_indexes, reverse=True):
				del rule_index[remove]	

# check for syntax errors in yara files
def test_c(yara_file):
	try:
		rules = yara.compile(yara_file)
		return 'success'
	except yara.SyntaxError, why:
		print 'Compile Error: %s' % str(why)

def main():
	if len(sys.argv) == 3 and sys.argv[2].lower() == 'skip':
		Yfile = yarafile(sys.argv[1])
		Yfile.extract()
		print Yfile
	elif test_c(sys.argv[1]) == 'success':
		Yfile = yarafile(sys.argv[1])
		Yfile.extract()
		print Yfile

	else:
		exit()

if __name__ == "__main__":
	main()
