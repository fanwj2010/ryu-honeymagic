import re 
import json

class SnortRuleParser(object):
    '''
    this will take an array of lines and parse it and hand back a dictionary
    '''
    def __init__(self):
        pass #gas
    
    def assemble(self,lines):
        buf = ''
        for line in lines:
            if line[-1:] == "\\":
                buf += line[:-1]
            else:
                buf+=line
        return buf

    def nonblank_lines(self,f):
        for l in f:
            line = l.rstrip()
            #line=l.strip()
            if line and not line.startswith("#"):
                yield line         
                      
    def parse(self,lines):
        if type(lines) != list:
            raise Exception('Input is not an array of strings') 
        
        line = self.assemble(lines)        
        #the text up to the first ( is the rule header
        # the section encclosed in the () are the rule options    
        res = re.search(r'(^.+)\((.+)\)',line)
        #make dict
        if res is not None:
           header = res.groups(1)[0]
           option = res.groups(1)[1]
        else:
           raise Exception('rule is blank') 
        #process the header by splitting on space
        headers = header.split()
        rule = {
                'action':headers[0],
                'protocol':headers[1],
                'srcaddr':headers[2],
                'srcport':headers[3],
                'direction':headers[4],
                'dstaddr':headers[5],
                'dstport':headers[6],
                'activatedynamic':None                
                }
        #attribute/value pairs
        ruleOptions = {}
        options = option.split(";")
        for opt in options:
            try:
                kv = opt.split(":")
                if kv[0].strip() == "msg" or "content":
                   plain_content = kv[1].replace("\"", "")
                   kv[1] = plain_content
                ruleOptions[kv[0].strip()] = kv[1]
            except Exception:
                pass
        rule['options'] = ruleOptions        
        return rule
