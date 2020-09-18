import queue,simplejson,os,threading,subprocess,requests
import warnings
import nmap
from socket import gethostbyname
warnings.filterwarnings(action='ignore')#通过警告过滤器进行控制不发出警告消息

class ScanXN:
	def __init__(self, keyword):
		self.pathd = '.\\'+keyword
		os.mkdir(self.pathd)
		self.crawl_result=self.pathd+'\\crawl_result_'+keyword+'.txt'
		self.sub_domains=self.pathd+'\\sub_domains_'+keyword+'.txt'
		self.ip_txt=self.pathd+'\\ip'+keyword+'.txt'

		self.urls_queue = queue.Queue()#使用多线程队列
		self.tclose=0

	def opt2File(self,paths):#爬虫的结果
		try:
			f = open(self.crawl_result,'a')
			f.write(paths + '\n')
		finally:
			f.close()

	def opt2File2(self,subdomains):
		try:
			f = open(self.sub_domains,'a')
			f.write(subdomains + '\n')
		finally:
			f.close()

	def request0(self):#利用request请求获取url,并使用xray扫描
		while self.tclose==0 or self.urls_queue.empty() == False:
			if(self.urls_queue.qsize()==0):
				continue
			print(self.urls_queue.qsize())#查看当前队列长度
			req =self.urls_queue.get()# 取出队列数据，没有数据将会等待
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
					self.opt2File(urls0)
				elif(method0=='POST'):
					a = requests.post(urls0, headers=headers0,data=data0, proxies=proxies,timeout=30,verify=False)#http post
					self.opt2File(urls0)
			except:
				continue
		return

	def crawler(self,target):#使用爬虫获取子域名，并添加队列
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
			self.opt2File2(subd)
		for req in req_list:
			# print('req',req)
			self.urls_queue.put(req)
		print("[scanning]")


	def get_host_ip(self,sub_domain):#子域名解析ip
		with open(sub_domain,'r') as f:
			for line in f.readlines():
				try:
					host = gethostbyname(line.strip('\n'))  # 域名反解析得到的IP
				except Exception as e:
					pass
				else:
					with open(self.ip_txt, 'a+') as r:  # ip.txt里面存储的是批量解析后的结果
						r.write(host + '\n')


	def nmap_http(self,ip):
		nm = nmap.PortScanner()
		try:
			nm.scan(ip, '80,8080,3128,8081,9080', '-sS')
			ports=[80,8080,3128,8081,9080]
			for port in ports:
				if nm[ip]['tcp'][port]['state']=='open' and nm[ip]['tcp'][port]['name']=='http':
					paths='http://'+ip+':'+str(port)
					print('nmap:',paths)
					self.opt2File(paths)
					self.crawler(paths)
		except:
			pass


if __name__ == '__main__':
	scan=ScanXN('test0917')	#	扫描之前修改任务名
	file = open("targets.txt")
	t = threading.Thread(target=scan.request0)
	t.start()
	for text in file.readlines():
		target_url = text.strip('\n')
		scan.crawler(target_url)
	tclose = 1
	scan.get_host_ip(scan.sub_domains)
	ipfile = open(scan.ip_txt)
	for text in ipfile.readlines():
		ip = text.strip('\n')
		if ip!='':
			print('ip:',ip)
			scan.nmap_http(ip)

