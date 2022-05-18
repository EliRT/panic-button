import re

import pandas as pd
import leveldb
import sqlite3

COMMON_ALERTS_WORDS = ['techsupport', 'alert', 'pc', 'security', 'windows', 'address', 'financial', 'message', 'email',
					   'using', 'virus', 'breach', 'tracking', 'carry', 'communications', 'ancient', 'result', 'call',
					   'stalkers', 'thefts', 'administrator', 'www', 'exe', 'hacked', 'logs', 'services', 'suspended',
					   'restart', 'situation', 'attention', 'duped', 'contacting', 'webcam', 'oops', 'passwords',
					   'registry', 'prevent', 'technicians', 'connection', 'adware', 'disabled', 'blocked', 'pop',
					   'access', 'reserved', 'run', 'worm', 'program', 'frame', 'live', 'live', 'warning', 'unknown',
					   'wrong', 'classified', 'info', 'attack', 'actions', 'desk', 'details', 'computing', 'inject',
					   'something', 'malware', 'calling', 'copyright', 'especially', 'technical', 'vpn', 'follow',
					   'harmful', 'response', 'engineering', 'anonymous', 'significant', 'shut', 'browsing', 'location',
					   'containing', 'dear', 'installed', 'visit', 'current', 'continue', 'causing', 'caused',
					   'exposed', 'apply', 'acts', 'useful', 'warriors', 'leaked', 'often', 'concealed', 'reason',
					   'tcp', 'theft', 'social', 'rights', 'firewall', 'major', 'disk', 'logins', 'identity', 'removed',
					   'hard', 'locked', 'cause', 'viruses', 'password', 'type', 'deleted', 'fix', 'page', 'auto',
					   'based form', 'port', 'com', 'trick', 'software', 'harmful', 'crash', 'terms']

if __name__ == "__main__":
	db = leveldb.LevelDB('../assets/levelDB')
	conn = sqlite3.connect('../assets/crawl-data.sqlite')
	cursor = conn.cursor()

	# df = pd.DataFrame(columns=['url', 'js_content'])
	df = pd.DataFrame(columns=['url', 'js_content', 'visit_id', 'top_level_url', 'alerts'] + COMMON_ALERTS_WORDS)

	cnt = 0
	columns = cursor.execute("SELECT url, content_hash, visit_id FROM http_responses")
	values = set(columns.fetchall())
	for value in values:
		cnt += 1
		print(cnt)
		url = value[0]
		key = value[1]
		visit_id = value[2]
		try:
			if key:
				content = db.Get(key.encode('utf-8'))
				if content:
					content = content.decode('utf-8')
					df = df.append({'url': url, 'js_content': content, 'visit_id' : visit_id}, ignore_index=True)
			if cnt == 1000:
				break
		except Exception:
			continue

for _, row in df.iterrows():
	visit_id = row['visit_id']
	columns = cursor.execute(f"SELECT top_level_url FROM javascript WHERE visit_id = {visit_id}")
	top_level_url = columns.fetchall()
	if top_level_url:
		top_level_url = top_level_url[0][0]
		row['top_level_url'] = top_level_url
	content = row['js_content']
	if 'alert' in content:
		alerts = re.findall(r'(?<=alert\(\").+(?=\")', content)
		if alerts:
			row['alerts'] = alerts
			for alert in alerts:
				for risk_word in COMMON_ALERTS_WORDS:
					if risk_word in alert:
						row[risk_word] = 1
						continue

df = df.dropna(subset=COMMON_ALERTS_WORDS, how='all')
df.drop('js_content', axis=1, inplace=True)
df.drop('alerts', axis=1, inplace=True)
df.to_csv('test.csv')
test = df
