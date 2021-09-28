#!/usr/bin/env python3
import requests
import re
import textwrap
from bs4 import BeautifulSoup
from markdown import markdown

# [TODO] refactor and clean up

response = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json').json()
print("package gctx\n\n")
knownNames = {}

for item in response['objects']:
    if 'type' in item:
        if 'attack-pattern' in item['type']:
            if item.get("revoked", ""):
                continue
            for e in item['external_references']:
                ext = e.get("external_id", "")
                if ext and e['source_name'] == "mitre-attack" :
                    name = "ATTACKEnt" + re.sub('[ -/()]', "", item['name'])
                    if knownNames.get(name, 0):
                        knownNames[name] = knownNames[name] + 1
                        name = name + str(knownNames[name])
                    else:
                        knownNames[name] = 1
                    
                    id = ext
                    phases = ""
                    for p in item['kill_chain_phases']:
                        phases = phases + p["phase_name"] + " "

                    soup = BeautifulSoup(markdown(item['description']), "html.parser")
                    text = ''.join(soup.findAll(text=True))
                    s = """
/* %s Phases: %s

%s
*/
func (g *Session) %s(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "%s").
        Msg("%s")
}""" % (name, phases.strip(), textwrap.fill(text, 80), name, id, item['name'].lower())
                    print(s)


response = requests.get('https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json').json()

for item in response['objects']:
    if 'type' in item:
        if 'attack-pattern' in item['type']:
            if item.get("revoked", ""):
                continue
            for e in item['external_references']:
                ext = e.get("external_id", "")
                if ext and e['source_name'] == "mitre-ics-attack":
                    name = "ATTACKICS" + re.sub('[ -/()]', "", item['name'])
                    if knownNames.get(name, 0):
                        knownNames[name] = knownNames[name] + 1
                        name = name + str(knownNames[name])
                    else:
                        knownNames[name] = 1
                    id = ext
                    phases = ""
                    for p in item['kill_chain_phases']:
                        phases = phases + p["phase_name"] + " "

                    soup = BeautifulSoup(markdown(item['description']), "html.parser")
                    text = ''.join(soup.findAll(text=True))
                 
                    s = """
/* %s Phases: %s

%s
*/
func (g *Session) %s(values ...Value) {
    l := g.addValues(values...)
    l.Warn().
        Str("technique", "%s").
        Msg("%s")
}""" % (name, phases.strip(), textwrap.fill(text, 80), name, id, item['name'].lower())
                    print(s)
