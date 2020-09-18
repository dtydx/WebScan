import queue,simplejson,os,threading,subprocess,requests
import warnings
import nmap
from socket import gethostbyname
warnings.filterwarnings(action='ignore')#通过警告过滤器进行控制不发出警告消息

keyword='suda' # 需要修改扫描目标文件
pathd = '.\\'+keyword
os.mkdir(pathd)
crawl_result=pathd+'\\crawl_result_'+keyword+'.txt'
sub_domains=pathd+'\\sub_domains_'+keyword+'.txt'
ip_txt=pathd+'\\ip'+keyword+'.txt'

urls_queue = queue.Queue()#使用多线程队列
tclose=0

def opt2File(paths):#爬虫的结果
	try:
		f = open(crawl_result,'a')
		f.write(paths + '\n')
	finally:
		f.close()

def opt2File2(subdomains):
	try:
		f = open(sub_domains,'a')
		f.write(subdomains + '\n')
	finally:
		f.close()

def request0():#利用request请求获取url,并使用xray扫描
	while tclose==0 or urls_queue.empty() == False:
		if(urls_queue.qsize()==0):
			continue
		print(urls_queue.qsize())#查看当前队列长度
		req =urls_queue.get()# 取出队列数据，没有数据将会等待
		proxies = {
		'http': 'http://127.0.0.1:7777',
		'https': 'http://127.0.0.1:7777',
		}
		urls0 =req['url']
		headers0 =req['headers']
		method0=req['method']
		data0=req['data']
		try:
			if(method0=='GET'):
				a = requests.get(urls0, headers=headers0, proxies=proxies,timeout=30,verify=False)#http get
				opt2File(urls0)
			elif(method0=='POST'):
				a = requests.post(urls0, headers=headers0,data=data0, proxies=proxies,timeout=30,verify=False)#http post
				opt2File(urls0)
		except:
			continue
	return

def crawler(target):#使用爬虫获取子域名，并添加队列
	cmd = ["./crawlergo", "-c", "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe","-t", "20","-f","smart","--fuzz-path", "--output-mode", "json", target]
	rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output, error = rsp.communicate()
	try:
		#print(output.decode().split("--[Mission Complete]--")[1])
		result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
	except:
		return
	req_list = result["req_list"]
	sub_domain = result["sub_domain_list"]
	print(target)
	print("[crawl ok]")
	for subd in sub_domain:#获取子域名
		opt2File2(subd)
	for req in req_list:
		# print('req',req)
		urls_queue.put(req)
	print("[scanning]")


def get_host_ip(sub_domain):#子域名解析ip
	with open(sub_domain,'r') as f:
		for line in f.readlines():
			try:
				host = gethostbyname(line.strip('\n'))  # 域名反解析得到的IP
			except Exception as e:
				pass
			else:
				with open(ip_txt, 'a+') as r:  # ip.txt里面存储的是批量解析后的结果
					r.write(host + '\n')


def nmap_http(ip):
	nm = nmap.PortScanner()
	try:
		nm.scan(ip, '80,8080,3128,8081,9080', '-sS')
		ports=[80,8080,3128,8081,9080]
		for port in ports:
			if nm[ip]['tcp'][port]['state']=='open' and nm[ip]['tcp'][port]['name']=='http':
				paths='http://'+ip+':'+str(port)
				print('nmap:',paths)
				opt2File(paths)
				crawler(paths)
	except:
		pass


if __name__ == '__main__':
	file = open("targets.txt")

	t = threading.Thread(target=request0)
	t.start()
	for text in file.readlines():
		target_url = text.strip('\n')
		crawler(target_url)
	tclose = 1
	get_host_ip(sub_domains)
	ipfile = open("ip.txt")
	for text in ipfile.readlines():
		ip = text.strip('\n')
		if ip!='':
			print('ip:',ip)
			nmap_http(ip)

