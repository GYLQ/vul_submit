#  -*-coding:utf8 -*-
# by 孤桜懶契
# 漏洞盒子刷洞脚本 by 2022.1.13
'''
0、所有初始化类中集合
1、session保存cookies，若cookies为null则使用发包和校验进行账号密码登陆
2、模拟浏览器，selenium浏览器drive，进行截图
3、发包获取上传图片链接
4、极验绕过验证码获取校验码
5、集成包体进行提交漏洞
'''

from selenium import webdriver
from urllib.parse import urlparse
import requests
import time
# import ast
import json
import httplib2
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
from PIL import ImageGrab
import random



class auto_init_butian:

    def __init__(self):
        '''
        初始化配置文件
        '''
        # Chrome的启动项参数，并实例化
        self.chromedriver_options = webdriver.ChromeOptions()
        self.chromedriver_options.add_experimental_option('useAutomationExtension', False)
        self.chromedriver_options.add_experimental_option("excludeSwitches", ['enable-automation'])
        self.chromedriver_options.add_argument('--incognito')
        self.chromedriver_options.add_argument('--ignore-certificate-errors')
        self.chromedriver_options.add_argument(r"--user-data-dir=C:\Users\23242\AppData\Local\Google\Chrome\User Data\Default");

        # 代理抓包测试配置
        self.proxies = {
            "http": 'http://127.0.0.1:8080',
            "https": 'http://127.0.0.1:8080'
        }

        # 滑块配置
        self.login_gt_url = "https://user.butian.net/register_geetest"
        self.submit_gt_url = "https://www.butian.net/Loo/startCaptcha"

        # 设定当前页面Cookie 和 登陆账号和密码
        self.session = requests.session()
        with open('user_config.txt' , 'r') as user_info:
            user_info = user_info.read()
            user_info = json.loads(user_info)
            # print(user_info)
        self.username = user_info["username"]
        self.password = user_info["password"]
        # 滑块 APikey
        self.appkey = user_info["appkey"]
        # 备案 APikey
        self.key = user_info["key"]

        # 判断是否设置了Cookie 设置了就用Cookie访问，如果没设置 就根据设置的账号和密码登陆
        if "null" not in user_info["cookie"][0]:
            print("[+] Cookies设置完毕，具体情况看结果!")
            self.session.cookies.set(user_info["cookie"][0],user_info["cookie"][1])
        else:
            self.login_user_pass()


    def submit_vul(self, url):
        '''
        将传入的url进行提交
        :param url:
        :return:
        '''
        company_vul_name=self.company_record_inquiry(url)
        # 当查询结果为个人，或无，都结束当前url的运行，继续下一个
        if company_vul_name == "failed":
            print("[-] 查询下一个")
            return

        # 截图
        self.screen_shot(url)

        # 分割
        url_parse = urlparse(url)
        host_name = url_parse.scheme+"://"+url_parse.netloc

        # 获取截图对应链接
        print("[*] ————主页截图————")
        image_first = self.upload_image('主页.png')
        print("[*] ————归属证明截图————")
        image_second = self.upload_image('归属证明.png')
        print("[*] ————信息泄露页面————")
        image_third = self.upload_image('信息泄露页面.png')

        # 详细描述过程
        detail = f'''<p>1、访问公司网站首页</p><p><br/></p><p><img src="{image_first}" title="" alt="image.png"/></p><p><br/></p><p><br/></p><p>2、备案归属查询截图</p><p><br/></p><p><img src="{image_second}" title="" alt="image.png"/></p><p><br/></p><p>3、验证漏洞，步骤如下</p><p>①漏洞所在URL：<a href="{url}">{url}</a> </p><p><br/></p><p>②直接访问上述漏洞URL，查看左下角下载文件</p><p><br/></p><p><img src="{image_third}" title="" alt="image.png"/></p>'''

        # 极验数据返回值 slider_dict['data']['challenge'], slider_dict['data']['validate']
        submit_challenge, submit_validate = self.pass_slider(sub_referer='https://www.butian.net/Loo/submit',sub_gt_url=self.submit_gt_url)

        # 元组表示表单上传的data数据

        files = {
            'attachment':(None,''),
            'attachment_name':(None,''),
            'url':(None,url),
            'attribute':(None,'1'), #漏洞类型，1：事件 2：通用
            'company_name':(None,company_vul_name),
            'host':(None,host_name),
            'origin':(None,'1'),
            'title':(None,company_vul_name+'当前网站存在信息泄露'),
            'type':(None,'10'),#漏洞类型， 2、sql注入 10、信息泄露
            'level':(None,'1'),#漏洞等级 1、中危 2、高危
            'description':(None,company_vul_name+'旗下网站存在信息泄露，攻击者可利用该漏洞获取大量敏感信息或源码对新的漏洞进行审计，从而进行更深入的攻击，导致更多的信息伤害。'),
            'detail':(None,detail),
            'repair_suggest':(None,'直接在该网站目录删除备份或敏感文件'),
            'tag3':(None,'class1|18,class2|19,class2|24'),# 标签选项
            'province':(None,'湖北省'),
            'city':(None,'武汉市'),
            'county':(None,'市辖区'),
            'company_contact':(None,''),
            'anonymous':(None,'1'),# 匿名提交
            'agree':(None,'1'),# 是否同意用户协议
            'id':(None,''),
            'geetest_challenge':(None,submit_challenge),#验证码
            'geetest_validate':(None,submit_validate),#验证码
            'geetest_seccode':(None,submit_validate+'|jordan'),#验证码
        }
        respon = self.session.post(url="https://www.butian.net/Home/Loo/submit",files=files,verify=False,timeout=5)
        sucess_result=json.loads(respon.text)
        sucess_message = str(sucess_result['info'])
        if sucess_result['status'] == 1:
            print("[+] 提交完成！")
            print("[*] 返回消息：",sucess_message)
            print("[+] 防止提交过快 随机延时 60-120 秒 请等待~~")
            start_time=time.time()
            time.sleep(random.randint(60, 120))
            end_time=time.time()
            print(f"[+] 已随机延时 { end_time - start_time:.2f} 秒，继续工作！\n")
        else:
            print("[-] 提交失败")
            print("[*] 返回消息：", sucess_message)
            print("[+] 防止提交过快 随机延时 60-120 秒 请等待~~")
            start_time=time.time()
            time.sleep(random.randint(60, 120))
            end_time=time.time()
            print(f"[+] 已随机延时 { end_time - start_time:.2f} 秒，继续工作！\n")




    # 图片上传
    def upload_image(self,image_path):
        '''
        对传上来的路径进行上传
        :param image_path:
        :return:
        '''
        read_binary_image = open(image_path, 'rb')
        files = {'upfile': read_binary_image}
        respon = requests.post("https://www.butian.net/Public/ueditor/php/controller.php?action=uploadimage",
                               files=files, verify=False, timeout=5)
        image_url = json.loads(respon.text)
        print("[+] 图片上传成功：", image_url['url'])
        return image_url['url']

    # 屏幕截图
    def screen_shot(self, url):
        '''
        访问对应url进行取证截图
        :param url:
        :return:
        '''

        # 浏览器启动
        self.chrome_browser = webdriver.Chrome(options=self.chromedriver_options)
        # 若上方报错，则如下采用路径形式
        # self.chrome_browser = webdriver.Chrome(executable_path=r'C:\python30\chromedriver.exe', options=self.chromedriver_options)
        # 窗口和加载设置
        self.chrome_browser.implicitly_wait(6) # 隐式等待
        self.chrome_browser.maximize_window() #窗口最大化

        # 截图大小
        screen_shot_size = (0, 0 , 1920, 1080)
        url_split = urlparse(url)
        # 访问归属
        self.chrome_browser.get("https://icp.chinaz.com/" + url_split.netloc)
        time.sleep(2)
        self.chrome_browser.execute_script("window.scrollTo(0,200);")
        screen_shot_image = ImageGrab.grab(screen_shot_size)
        screen_shot_image.save('归属证明.png')

        # 访问主页
        self.chrome_browser.get("http://"+url_split.netloc)
        time.sleep(2)
        screen_shot_image = ImageGrab.grab(screen_shot_size)
        screen_shot_image.save('主页.png')

        # 访问信息泄露的url
        self.chrome_browser.get(url)
        time.sleep(2)
        screen_shot_image = ImageGrab.grab(screen_shot_size)
        screen_shot_image.save('信息泄露页面.png')
        self.chrome_browser.close()


    # 备案信息收集 ↓
    def company_record_inquiry(self,url):
        '''
        备案查询
        :param url:
        :return:
        '''
        print("[*] 查询备案公司信息："+url)
        url_domain=urlparse(url).netloc
        # Api备案查询 ↓ http://api.chinaz.com/ApiDetails/Domain 积分购买
        api_information=f"https://apidatav2.chinaz.com/single/icp?key={self.key}&domain="+url_domain
        respon=requests.get(url=api_information,timeout=5)
        # if ('null' in rsp.text):
        #     return "shibai"
        # Json转字典——Json.loads(respon.text)
        # 将数据转换成能够转换的类型 ast.literal_eval(respon.text) 当域名错误时会报错 弃用
        dict_convert=json.loads(respon.text)
        if "null" in respon.text:
             print("[-] 数据未查询到")
             return "failed"
        elif dict_convert["Result"]["CompanyType"] == "个人":  # 当网站为个人时 数据用处不大
            print("[*] 当前域名用户为个人产业")
            print("[-] 无法提交漏洞")
            return "failed"
        elif dict_convert["StateCode"] == 1:  # 查询成功，不是个人返回
            print("[+] 查询成功")
            print("[+] 数据为：",dict_convert["Result"]["CompanyName"])
            return dict_convert["Result"]["CompanyName"]
        return "failed"

    # 付费过任何滑块
    def pass_slider(self,sub_referer,sub_gt_url):
        '''
        滑块方法
        :param sub_referer:
        :param sub_gt_url:
        :return:
        '''
        # 用户appkey
        appkey = self.appkey  # https://www.kancloud.cn/rrocr/rrocr/2294925 获取apk
        # 判断获取challenge 和 gt的位置是否能够访问

        try:
            # 获取gt 和 challenge
            gt_url = sub_gt_url
            gt_rep = requests.get(url=gt_url, verify=False)
            gt_dict = json.loads(gt_rep.text)
            gt = gt_dict['gt']
            challenge = gt_dict["challenge"]
            print("[+] 获取成功 gt:", gt, " challenge:", challenge)
        except:
            print('[-] 正在尝试访问获取gt和challenge页面')
            self.pass_slider(sub_referer,sub_gt_url)
        # 查询当前api剩余积分
        try:
            slider_req_score = f"http://api.rrocr.com/api/integral.html?appkey={appkey}"
            slider_rep_score = requests.get(url=slider_req_score)
            print("[+] 当前极验剩余Api积分：", json.loads(slider_rep_score.text)['integral'])
        except:
            print("[-] 积分无法查询，请确认appkey正确!")
            exit(1)

        slider_data = {
            'appkey': appkey,
            'gt': gt_dict['gt'],
            'challenge': gt_dict['challenge'],
            'referer': sub_referer
        }
        # 传参判断返回值
        try:
            slider_rep = requests.post(url='http://api.rrocr.com/api/recognize.html', data=slider_data)
            if "识别成功" in slider_rep.text:
                slider_dict = json.loads(slider_rep.text)
                # print(slider_dict)
                print("[+] 校验成功 challenge:",slider_dict['data']['challenge'], "validate:",slider_dict['data']['validate'])
                return slider_dict['data']['challenge'], slider_dict['data']['validate']
            else:
                print("[-] 识别失败，请确认是否还剩余积分！")
        except:
            print("[-] 无法访问 api对应网站")

    def login_user_pass(self):
        '''
        账号密码登陆
        :return:
        '''
        print("[*] 正在尝试账号密码登陆~")
        # 获取请求包体
        requests_headers = httplib2.Http('.cache')
        url = 'https://user.butian.net/user/sign-in?next=https://www.butian.net/login.html&style=1'
        response, content = requests_headers.request(url, 'GET')
        response = dict(response)
        # 从包体中获取csrf形成字典形式
        set_cookie_split = response['set-cookie'].split(';')
        csrf_split = set_cookie_split[0].split('=')
        print("[+] csrf_token保护获取成功：", csrf_split[1])
        suc_challenge, suc_validate = self.pass_slider(sub_referer='https://user.butian.net/user/sign-in?next=https://www.butian.net/login.html&style=1',sub_gt_url=self.login_gt_url)
        print("[+] 识别成功，challenge:", suc_challenge, "validate:", suc_validate)
        login_url = "https://user.butian.net/api/v1/sign-in"
        login_data = {
            "account": self.username,
            "password": self.password,
            "geetest_challenge": suc_challenge,
            "geetest_validate": suc_validate,
            "geetest_seccode": suc_validate + "|jordan",
            "next": "https://www.butian.net/login.html",
            "csrf_token": csrf_split[1]
        }
        login_headers = {
            'Cookie': 'next=https%3A//www.butian.net/login.html; User-Center=17507e8a-c16a-40c1-b401-f0f1c9658a11; style=1; csrf_token=' +
                      csrf_split[1],
            'Sec-Ch-Ua': '"Chromium";v="91", " Not;A Brand";v="99"',
            'Accept': 'application/json',
            'Sec-Ch-Ua-Mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Content-Type': 'application/json',
            'Origin': 'https://user.butian.net',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://user.butian.net/user/sign-in?next=https://www.butian.net/login.html&style=1',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close',
        }
        login_rep = self.session.post(url=login_url, data=json.dumps(login_data), headers=login_headers,
                                 verify=False)
        if r"\u6210\u529f" in login_rep.text:
            print("[+] 登陆成功！\n")
        else:
            print("[-] 密码错误！请重新输入或者更换成Cookie方式！\n")




if __name__ == '__main__':
    auto_start = auto_init_butian()  # 初始化数据，登陆和cookie设置
    with open("url.txt", "r") as file:
        file_line_list = file.read().split("\n")
        count = 1
        for vul_url in file_line_list:
            print("[*] 剩下数量：", count, "/", len(file_line_list))
            auto_start.submit_vul(vul_url)
            count += 1