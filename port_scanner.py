import customtkinter as ctk
import threading
import socket
import queue
import time
import requests
import json
import dns.resolver
import os
import re
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
from urllib.parse import urljoin, urlparse

# AI API导入
import openai
import google.generativeai as genai
from anthropic import Anthropic
from openai import OpenAI

class Scanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # 设置主题和外观
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # 配置窗口
        self.title("通用扫描器")
        self.geometry("1000x800")  # 增加窗口大小
        self.minsize(1000, 800)
        
        # 初始化变量
        self.scan_thread = None
        self.stop_scan = False
        self.result_queue = queue.Queue()
        
        # 初始化AI API密钥和地址
        self.ai_api_keys = {
            'openai': '',
            'gemini': '',
            'anthropic': '',
            'deepseek': '',
            'kimi': ''  # 添加Kimi API密钥
        }
        
        # 初始化AI API地址
        self.ai_api_urls = {
            'openai': 'https://api.openai.com/v1/chat/completions',
            'gemini': 'https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent',
            'anthropic': 'https://api.anthropic.com/v1/messages',
            'deepseek': 'https://api.deepseek.com/v1/chat/completions',
            'kimi': 'https://api.moonshot.cn/v1/chat/completions'
        }
        
        # 创建主框架
        self.create_widgets()
        
    def create_widgets(self):
        # 创建选项卡
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 添加所有选项卡
        self.port_tab = self.tabview.add("端口扫描")
        self.dir_tab = self.tabview.add("目录扫描")
        self.subdomain_tab = self.tabview.add("子域名爆破")
        self.poc_tab = self.tabview.add("POC测试")
        self.ip_trace_tab = self.tabview.add("IP溯源")
        self.code_audit_tab = self.tabview.add("代码审计")  # 新增代码审计选项卡
        
        # 创建各个界面
        self.create_port_scan_widgets()
        self.create_dir_scan_widgets()
        self.create_subdomain_scan_widgets()
        self.create_poc_test_widgets()
        self.create_ip_trace_widgets()
        self.create_code_audit_widgets()  # 新增代码审计界面
        
    def create_port_scan_widgets(self):
        # 创建左侧面板
        left_frame = ctk.CTkFrame(self.port_tab)
        left_frame.pack(side="left", fill="y", padx=10, pady=10)
        
        # IP输入
        ip_label = ctk.CTkLabel(left_frame, text="目标IP地址:", font=("微软雅黑", 12))
        ip_label.pack(pady=5)
        self.ip_entry = ctk.CTkEntry(left_frame, width=200)
        self.ip_entry.pack(pady=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        # 端口范围输入
        port_frame = ctk.CTkFrame(left_frame)
        port_frame.pack(pady=10)
        
        start_label = ctk.CTkLabel(port_frame, text="起始端口:", font=("微软雅黑", 12))
        start_label.pack(side="left", padx=5)
        self.start_port = ctk.CTkEntry(port_frame, width=70)
        self.start_port.pack(side="left", padx=5)
        self.start_port.insert(0, "1")
        
        end_label = ctk.CTkLabel(port_frame, text="结束端口:", font=("微软雅黑", 12))
        end_label.pack(side="left", padx=5)
        self.end_port = ctk.CTkEntry(port_frame, width=70)
        self.end_port.pack(side="left", padx=5)
        self.end_port.insert(0, "1024")
        
        # 线程数选择
        thread_label = ctk.CTkLabel(left_frame, text="扫描线程数:", font=("微软雅黑", 12))
        thread_label.pack(pady=5)
        self.thread_slider = ctk.CTkSlider(left_frame, from_=1, to=100, number_of_steps=99)
        self.thread_slider.pack(pady=5)
        self.thread_slider.set(50)
        
        # 超时设置
        timeout_label = ctk.CTkLabel(left_frame, text="连接超时(秒):", font=("微软雅黑", 12))
        timeout_label.pack(pady=5)
        self.timeout_slider = ctk.CTkSlider(left_frame, from_=0.1, to=5.0, number_of_steps=49)
        self.timeout_slider.pack(pady=5)
        self.timeout_slider.set(1.0)
        
        # 控制按钮
        self.port_start_button = ctk.CTkButton(left_frame, text="开始扫描", command=self.start_port_scan)
        self.port_start_button.pack(pady=10)
        
        self.port_stop_button = ctk.CTkButton(left_frame, text="停止扫描", command=self.stop_scanning, state="disabled")
        self.port_stop_button.pack(pady=5)
        
        # 创建右侧结果显示区域
        right_frame = ctk.CTkFrame(self.port_tab)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # 进度条
        self.port_progress_var = ctk.DoubleVar()
        self.port_progress_bar = ctk.CTkProgressBar(right_frame)
        self.port_progress_bar.pack(fill="x", padx=10, pady=5)
        self.port_progress_bar.set(0)
        
        # 状态标签
        self.port_status_label = ctk.CTkLabel(right_frame, text="就绪", font=("微软雅黑", 12))
        self.port_status_label.pack(pady=5)
        
        # 结果表格
        columns = ("端口", "状态", "服务")
        self.port_result_tree = ttk.Treeview(right_frame, columns=columns, show="headings")
        
        # 设置列标题
        for col in columns:
            self.port_result_tree.heading(col, text=col)
            self.port_result_tree.column(col, width=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=self.port_result_tree.yview)
        self.port_result_tree.configure(yscrollcommand=scrollbar.set)
        
        self.port_result_tree.pack(fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")

    def create_dir_scan_widgets(self):
        # 创建左侧面板
        left_frame = ctk.CTkFrame(self.dir_tab)
        left_frame.pack(side="left", fill="y", padx=10, pady=10)
        
        # URL输入
        url_label = ctk.CTkLabel(left_frame, text="目标URL:", font=("微软雅黑", 12))
        url_label.pack(pady=5)
        self.url_entry = ctk.CTkEntry(left_frame, width=200)
        self.url_entry.pack(pady=5)
        self.url_entry.insert(0, "http://example.com")
        
        # 字典选择框架
        dict_frame = ctk.CTkFrame(left_frame)
        dict_frame.pack(pady=10, fill="x", padx=5)
        
        # 字典类型选择
        self.dict_var = ctk.StringVar(value="内置字典")
        dict_label = ctk.CTkLabel(dict_frame, text="字典类型:", font=("微软雅黑", 12))
        dict_label.pack(pady=5)
        dict_options = ["内置字典", "自定义字典"]
        self.dict_menu = ctk.CTkOptionMenu(dict_frame, values=dict_options, variable=self.dict_var, command=self.on_dict_type_change)
        self.dict_menu.pack(pady=5)
        
        # 内置字典选择
        self.builtin_dict_frame = ctk.CTkFrame(left_frame)
        self.builtin_dict_frame.pack(pady=5, fill="x", padx=5)
        
        self.builtin_dict_var = ctk.StringVar(value="常用目录")
        builtin_options = ["常用目录", "敏感文件", "后台路径"]
        self.builtin_dict_menu = ctk.CTkOptionMenu(self.builtin_dict_frame, values=builtin_options, variable=self.builtin_dict_var)
        self.builtin_dict_menu.pack(pady=5)
        
        # 自定义字典框架
        self.custom_dict_frame = ctk.CTkFrame(left_frame)
        
        # 文件选择按钮
        self.select_file_button = ctk.CTkButton(self.custom_dict_frame, text="选择字典文件", command=self.select_dict_file)
        self.select_file_button.pack(pady=5)
        
        # 显示选中的文件路径
        self.file_path_label = ctk.CTkLabel(self.custom_dict_frame, text="未选择文件", font=("微软雅黑", 10))
        self.file_path_label.pack(pady=5)
        
        # 或者手动输入
        self.custom_dict_label = ctk.CTkLabel(self.custom_dict_frame, text="或直接输入字典内容\n(每行一个路径)", font=("微软雅黑", 10))
        self.custom_dict_label.pack(pady=5)
        
        self.custom_dict_text = ctk.CTkTextbox(self.custom_dict_frame, height=100)
        self.custom_dict_text.pack(pady=5, fill="x", padx=5)
        
        # 线程数选择
        thread_label = ctk.CTkLabel(left_frame, text="扫描线程数:", font=("微软雅黑", 12))
        thread_label.pack(pady=5)
        self.dir_thread_slider = ctk.CTkSlider(left_frame, from_=1, to=50, number_of_steps=49)
        self.dir_thread_slider.pack(pady=5)
        self.dir_thread_slider.set(10)
        
        # 超时设置
        timeout_label = ctk.CTkLabel(left_frame, text="请求超时(秒):", font=("微软雅黑", 12))
        timeout_label.pack(pady=5)
        self.dir_timeout_slider = ctk.CTkSlider(left_frame, from_=1, to=10.0, number_of_steps=90)
        self.dir_timeout_slider.pack(pady=5)
        self.dir_timeout_slider.set(3.0)
        
        # 控制按钮
        self.dir_start_button = ctk.CTkButton(left_frame, text="开始扫描", command=self.start_dir_scan)
        self.dir_start_button.pack(pady=10)
        
        self.dir_stop_button = ctk.CTkButton(left_frame, text="停止扫描", command=self.stop_scanning, state="disabled")
        self.dir_stop_button.pack(pady=5)
        
        # 创建右侧结果显示区域
        right_frame = ctk.CTkFrame(self.dir_tab)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # 进度条
        self.dir_progress_var = ctk.DoubleVar()
        self.dir_progress_bar = ctk.CTkProgressBar(right_frame)
        self.dir_progress_bar.pack(fill="x", padx=10, pady=5)
        self.dir_progress_bar.set(0)
        
        # 状态标签
        self.dir_status_label = ctk.CTkLabel(right_frame, text="就绪", font=("微软雅黑", 12))
        self.dir_status_label.pack(pady=5)
        
        # 结果表格
        columns = ("URL", "状态码", "大小(KB)")
        self.dir_result_tree = ttk.Treeview(right_frame, columns=columns, show="headings")
        
        # 设置列标题
        for col in columns:
            self.dir_result_tree.heading(col, text=col)
            self.dir_result_tree.column(col, width=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=self.dir_result_tree.yview)
        self.dir_result_tree.configure(yscrollcommand=scrollbar.set)
        
        self.dir_result_tree.pack(fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # 初始化显示内置字典框架
        self.on_dict_type_change("内置字典")

    def on_dict_type_change(self, choice):
        if choice == "内置字典":
            self.custom_dict_frame.pack_forget()
            self.builtin_dict_frame.pack(pady=5, fill="x", padx=5)
        else:
            self.builtin_dict_frame.pack_forget()
            self.custom_dict_frame.pack(pady=5, fill="x", padx=5)

    def select_dict_file(self):
        file_path = filedialog.askopenfilename(
            title="选择字典文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path_label.configure(text=file_path)
            # 读取文件内容并显示在文本框中
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.custom_dict_text.delete("0.0", "end")
                    self.custom_dict_text.insert("0.0", content)
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败: {str(e)}")

    def scan_port(self, ip, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "未知"
                    self.result_queue.put(("port", port, "开放", service))
                return result == 0
        except:
            return False

    def scan_directory(self, base_url, path, timeout):
        try:
            url = urljoin(base_url, path.strip())
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            if response.status_code != 404:
                size = len(response.content) / 1024  # 转换为KB
                self.result_queue.put(("dir", url, response.status_code, f"{size:.2f}"))
            return True
        except:
            return False

    def get_directory_list(self):
        if self.dict_var.get() == "内置字典":
            # 内置字典
            common_dirs = ["/admin", "/login", "/wp-admin", "/dashboard", "/images", "/upload", 
                          "/static", "/api", "/include", "/includes", "/css", "/js", "/javascript",
                          "/styles", "/docs", "/documentation", "/test", "/temp", "/tmp", "/dev",
                          "/backup", "/bak", "/old", "/new", "/beta", "/php", "/phpinfo.php"]
                          
            sensitive_files = ["/config.php", "/wp-config.php", "/.env", "/.git/config", 
                              "/composer.json", "/package.json", "/web.config", "/.htaccess",
                              "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/README.md",
                              "/LICENSE", "/CHANGELOG.md", "/phpinfo.php", "/info.php"]
                              
            admin_paths = ["/admin", "/administrator", "/wp-admin", "/cms", "/control", 
                          "/manage", "/management", "/manager", "/admin.php", "/admin.html",
                          "/login", "/login.php", "/cp", "/cpanel", "/webadmin", "/myadmin",
                          "/master", "/dashboard", "/auth", "/backend", "/admin-panel"]

            dict_type = self.builtin_dict_var.get()
            if dict_type == "敏感文件":
                return sensitive_files
            elif dict_type == "后台路径":
                return admin_paths
            else:
                return common_dirs
        else:
            # 自定义字典
            custom_content = self.custom_dict_text.get("0.0", "end").strip()
            if not custom_content:
                messagebox.showwarning("警告", "自定义字典为空，请输入扫描路径或选择字典文件")
                return []
            return [line.strip() for line in custom_content.split('\n') if line.strip()]

    def scan_ports(self):
        ip = self.ip_entry.get()
        start_port = int(self.start_port.get())
        end_port = int(self.end_port.get())
        timeout = self.timeout_slider.get()
        
        total_ports = end_port - start_port + 1
        scanned_ports = 0
        
        for port in range(start_port, end_port + 1):
            if self.stop_scan:
                break
                
            self.scan_port(ip, port, timeout)
            scanned_ports += 1
            progress = scanned_ports / total_ports
            self.port_progress_var.set(progress)
            self.port_progress_bar.set(progress)
            
            # 更新状态
            self.port_status_label.configure(text=f"正在扫描端口 {port}/{end_port}")
            
        if not self.stop_scan:
            self.port_status_label.configure(text="扫描完成")
        else:
            self.port_status_label.configure(text="扫描已停止")
            
        self.port_start_button.configure(state="normal")
        self.port_stop_button.configure(state="disabled")
        self.stop_scan = False

    def scan_directories(self):
        base_url = self.url_entry.get()
        timeout = self.dir_timeout_slider.get()
        directories = self.get_directory_list()
        
        total_dirs = len(directories)
        scanned_dirs = 0
        
        for directory in directories:
            if self.stop_scan:
                break
                
            self.scan_directory(base_url, directory, timeout)
            scanned_dirs += 1
            progress = scanned_dirs / total_dirs
            self.dir_progress_var.set(progress)
            self.dir_progress_bar.set(progress)
            
            # 更新状态
            self.dir_status_label.configure(text=f"正在扫描 {scanned_dirs}/{total_dirs}")
            
        if not self.stop_scan:
            self.dir_status_label.configure(text="扫描完成")
        else:
            self.dir_status_label.configure(text="扫描已停止")
            
        self.dir_start_button.configure(state="normal")
        self.dir_stop_button.configure(state="disabled")
        self.stop_scan = False

    def update_results(self):
        while True:
            try:
                result = self.result_queue.get_nowait()
                if result[0] == "port":
                    _, port, status, service = result
                    self.port_result_tree.insert("", "end", values=(port, status, service))
                elif result[0] == "dir":
                    _, url, status_code, size = result
                    self.dir_result_tree.insert("", "end", values=(url, status_code, size))
                elif result[0] == "subdomain":
                    _, domain, ip_addresses, status = result
                    self.subdomain_result_tree.insert("", "end", values=(domain, ip_addresses, status))
                elif result[0] == "audit":
                    _, vuln = result
                    # 插入审计结果到树形视图
                    self.audit_result_tree.insert("", "end", values=(
                        vuln['file'],
                        vuln['type'],
                        vuln['line'],
                        vuln['level'],
                        vuln['description'],
                        vuln.get('code', '')  # 添加代码片段
                    ))
                    # 自动滚动到最新结果
                    self.audit_result_tree.yview_moveto(1)
            except queue.Empty:
                break
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.after(100, self.update_results)

    def start_port_scan(self):
        # 清空之前的结果
        for item in self.port_result_tree.get_children():
            self.port_result_tree.delete(item)
            
        self.port_start_button.configure(state="disabled")
        self.port_stop_button.configure(state="normal")
        self.port_progress_bar.set(0)
        
        self.scan_thread = threading.Thread(target=self.scan_ports)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.update_results()

    def start_dir_scan(self):
        # 清空之前的结果
        for item in self.dir_result_tree.get_children():
            self.dir_result_tree.delete(item)
            
        self.dir_start_button.configure(state="disabled")
        self.dir_stop_button.configure(state="normal")
        self.dir_progress_bar.set(0)
        
        self.scan_thread = threading.Thread(target=self.scan_directories)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.update_results()

    def stop_scanning(self):
        self.stop_scan = True
        if self.tabview.get() == "端口扫描":
            self.port_stop_button.configure(state="disabled")
        elif self.tabview.get() == "目录扫描":
            self.dir_stop_button.configure(state="disabled")
        else:
            self.poc_stop_button.configure(state="disabled")

    def create_poc_test_widgets(self):
        # 创建左侧面板
        left_frame = ctk.CTkFrame(self.poc_tab)
        left_frame.pack(side="left", fill="y", padx=10, pady=10, expand=True)
        
        # URL输入
        url_label = ctk.CTkLabel(left_frame, text="目标URL:", font=("微软雅黑", 12))
        url_label.pack(pady=5)
        self.poc_url_entry = ctk.CTkEntry(left_frame, width=300)  # 加宽URL输入框
        self.poc_url_entry.pack(pady=5)
        self.poc_url_entry.insert(0, "http://example.com")
        
        # POC编辑区域
        poc_label = ctk.CTkLabel(left_frame, text="POC代码:", font=("微软雅黑", 12))
        poc_label.pack(pady=5)
        
        # POC模板选择
        template_frame = ctk.CTkFrame(left_frame)
        template_frame.pack(fill="x", pady=5)
        
        template_label = ctk.CTkLabel(template_frame, text="快速模板:", font=("微软雅黑", 10))
        template_label.pack(side="left", padx=5)
        
        templates = ["GET请求", "POST请求", "命令执行", "SQL注入", "文件包含"]
        self.poc_template_var = ctk.StringVar(value="GET请求")
        self.poc_template_menu = ctk.CTkOptionMenu(template_frame, values=templates, 
                                                 variable=self.poc_template_var,
                                                 command=self.load_poc_template,
                                                 width=120)
        self.poc_template_menu.pack(side="left", padx=5)
        
        # 文件操作按钮
        button_frame = ctk.CTkFrame(template_frame)
        button_frame.pack(side="right", padx=5)
        
        self.load_poc_button = ctk.CTkButton(button_frame, text="加载POC", 
                                           command=self.load_poc_file, width=90)
        self.load_poc_button.pack(side="left", padx=5)
        
        self.save_poc_button = ctk.CTkButton(button_frame, text="保存POC", 
                                           command=self.save_poc_file, width=90)
        self.save_poc_button.pack(side="left", padx=5)
        
        # POC代码编辑框 - 增加高度并使用等宽字体
        self.poc_code_text = ctk.CTkTextbox(left_frame, 
                                          height=400,  # 增加高度
                                          font=("Consolas", 12),
                                          wrap="none")  # 禁用自动换行
        self.poc_code_text.pack(pady=5, fill="both", expand=True, padx=5)
        
        # 加载默认模板
        self.load_poc_template("GET请求")
        
        # 请求设置
        settings_frame = ctk.CTkFrame(left_frame)
        settings_frame.pack(fill="x", pady=10, padx=5)
        
        # 超时设置
        timeout_frame = ctk.CTkFrame(settings_frame)
        timeout_frame.pack(side="left", fill="x", expand=True, padx=5)
        
        timeout_label = ctk.CTkLabel(timeout_frame, text="请求超时(秒):", font=("微软雅黑", 12))
        timeout_label.pack()
        self.poc_timeout_slider = ctk.CTkSlider(timeout_frame, from_=1, to=30.0, number_of_steps=29)
        self.poc_timeout_slider.pack(fill="x", padx=5)
        self.poc_timeout_slider.set(5.0)
        
        # 重试次数
        retry_frame = ctk.CTkFrame(settings_frame)
        retry_frame.pack(side="right", fill="x", expand=True, padx=5)
        
        retry_label = ctk.CTkLabel(retry_frame, text="重试次数:", font=("微软雅黑", 12))
        retry_label.pack()
        self.retry_slider = ctk.CTkSlider(retry_frame, from_=0, to=5, number_of_steps=5)
        self.retry_slider.pack(fill="x", padx=5)
        self.retry_slider.set(2)
        
        # 控制按钮
        control_frame = ctk.CTkFrame(left_frame)
        control_frame.pack(fill="x", pady=5, padx=5)
        
        self.poc_start_button = ctk.CTkButton(control_frame, text="开始测试", 
                                            command=self.start_poc_test)
        self.poc_start_button.pack(side="left", padx=5, expand=True)
        
        self.poc_stop_button = ctk.CTkButton(control_frame, text="停止测试", 
                                           command=self.stop_scanning, state="disabled")
        self.poc_stop_button.pack(side="right", padx=5, expand=True)
        
        # 创建右侧结果显示区域
        right_frame = ctk.CTkFrame(self.poc_tab)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # 进度条
        self.poc_progress_var = ctk.DoubleVar()
        self.poc_progress_bar = ctk.CTkProgressBar(right_frame)
        self.poc_progress_bar.pack(fill="x", padx=10, pady=5)
        self.poc_progress_bar.set(0)
        
        # 状态标签
        self.poc_status_label = ctk.CTkLabel(right_frame, text="就绪", font=("微软雅黑", 12))
        self.poc_status_label.pack(pady=5)
        
        # 测试结果文本框
        self.poc_result_text = ctk.CTkTextbox(right_frame, font=("Consolas", 12))
        self.poc_result_text.pack(fill="both", expand=True, pady=5)

    def load_poc_template(self, template_name):
        templates = {
            "GET请求": '''{
    "method": "GET",
    "path": "/path/to/test",
    "headers": {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    },
    "params": {
        "id": "1"
    },
    "success_condition": {
        "status_code": 200,
        "contains": "sensitive_data"
    }
}''',
            "POST请求": '''{
    "method": "POST",
    "path": "/api/endpoint",
    "headers": {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    },
    "data": {
        "username": "admin",
        "password": "password123"
    },
    "success_condition": {
        "status_code": 200,
        "contains": "login_success"
    }
}''',
            "命令执行": '''{
    "method": "POST",
    "path": "/vulnerable/endpoint",
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded"
    },
    "data": {
        "cmd": "id",
        "submit": "Execute"
    },
    "success_condition": {
        "status_code": 200,
        "contains": "uid="
    }
}''',
            "SQL注入": '''{
    "method": "GET",
    "path": "/article",
    "params": {
        "id": "1' OR '1'='1"
    },
    "success_condition": {
        "status_code": 200,
        "contains": "admin"
    }
}''',
            "文件包含": '''{
    "method": "GET",
    "path": "/include",
    "params": {
        "file": "../../../etc/passwd"
    },
    "success_condition": {
        "status_code": 200,
        "contains": "root:"
    }
}'''
        }
        
        self.poc_code_text.delete("0.0", "end")
        self.poc_code_text.insert("0.0", templates.get(template_name, ""))

    def load_poc_file(self):
        file_path = filedialog.askopenfilename(
            title="加载POC文件",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # 验证JSON格式
                    json.loads(content)
                    self.poc_code_text.delete("0.0", "end")
                    self.poc_code_text.insert("0.0", content)
            except json.JSONDecodeError:
                messagebox.showerror("错误", "无效的JSON格式")
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败: {str(e)}")

    def save_poc_file(self):
        file_path = filedialog.asksaveasfilename(
            title="保存POC文件",
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                content = self.poc_code_text.get("0.0", "end").strip()
                # 验证JSON格式
                json.loads(content)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("成功", "POC文件保存成功")
            except json.JSONDecodeError:
                messagebox.showerror("错误", "无效的JSON格式")
            except Exception as e:
                messagebox.showerror("错误", f"保存文件失败: {str(e)}")

    def execute_poc(self, url, poc_config, timeout):
        try:
            # 构建完整URL
            full_url = urljoin(url, poc_config.get("path", ""))
            
            # 准备请求参数
            method = poc_config.get("method", "GET")
            headers = poc_config.get("headers", {})
            params = poc_config.get("params", {})
            data = poc_config.get("data", {})
            
            # 发送请求
            response = requests.request(
                method=method,
                url=full_url,
                headers=headers,
                params=params,
                json=data if headers.get("Content-Type") == "application/json" else None,
                data=data if headers.get("Content-Type") != "application/json" else None,
                timeout=timeout,
                verify=False
            )
            
            # 检查成功条件
            success_condition = poc_config.get("success_condition", {})
            expected_status = success_condition.get("status_code")
            expected_content = success_condition.get("contains")
            
            is_vulnerable = True
            if expected_status and response.status_code != expected_status:
                is_vulnerable = False
            if expected_content and expected_content not in response.text:
                is_vulnerable = False
            
            # 返回结果
            result = {
                "status_code": response.status_code,
                "response_size": len(response.content),
                "is_vulnerable": is_vulnerable,
                "response_headers": dict(response.headers),
                "response_text": response.text[:500] + "..." if len(response.text) > 500 else response.text
            }
            
            return result
            
        except Exception as e:
            return {
                "error": str(e),
                "is_vulnerable": False
            }

    def start_poc_test(self):
        # 清空之前的结果
        self.poc_result_text.delete("0.0", "end")
        self.poc_progress_bar.set(0)
        
        # 获取参数
        url = self.poc_url_entry.get()
        timeout = self.poc_timeout_slider.get()
        max_retries = int(self.retry_slider.get())
        
        try:
            # 解析POC配置
            poc_config = json.loads(self.poc_code_text.get("0.0", "end"))
        except json.JSONDecodeError:
            messagebox.showerror("错误", "POC格式错误，请检查JSON语法")
            return
        
        # 更新界面状态
        self.poc_start_button.configure(state="disabled")
        self.poc_stop_button.configure(state="normal")
        self.poc_status_label.configure(text="正在测试...")
        
        def run_test():
            retry_count = 0
            while retry_count <= max_retries and not self.stop_scan:
                if retry_count > 0:
                    self.poc_status_label.configure(text=f"重试第 {retry_count} 次...")
                
                result = self.execute_poc(url, poc_config, timeout)
                
                if "error" not in result or retry_count == max_retries:
                    break
                    
                retry_count += 1
                time.sleep(1)
            
            # 在主线程中更新UI
            self.after(0, self.update_poc_result, result)
            
        # 启动测试线程
        self.scan_thread = threading.Thread(target=run_test)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def update_poc_result(self, result):
        self.poc_progress_bar.set(1)
        
        if "error" in result:
            self.poc_status_label.configure(text="测试失败")
            self.poc_result_text.insert("end", f"错误: {result['error']}\n")
        else:
            status = "存在漏洞" if result["is_vulnerable"] else "未发现漏洞"
            self.poc_status_label.configure(text=f"测试完成 - {status}")
            
            # 格式化输出结果
            output = f"""测试结果:
状态: {status}
响应状态码: {result['status_code']}
响应大小: {result['response_size']} 字节

响应头:
{json.dumps(result['response_headers'], indent=2, ensure_ascii=False)}

响应内容:
{result['response_text']}
"""
            self.poc_result_text.insert("end", output)
        
        self.poc_start_button.configure(state="normal")
        self.poc_stop_button.configure(state="disabled")

    def create_subdomain_scan_widgets(self):
        # 创建左侧面板
        left_frame = ctk.CTkFrame(self.subdomain_tab)
        left_frame.pack(side="left", fill="y", padx=10, pady=10)
        
        # 域名输入
        domain_label = ctk.CTkLabel(left_frame, text="目标域名:", font=("微软雅黑", 12))
        domain_label.pack(pady=5)
        self.domain_entry = ctk.CTkEntry(left_frame, width=200)
        self.domain_entry.pack(pady=5)
        self.domain_entry.insert(0, "example.com")
        
        # 字典选择框架
        dict_frame = ctk.CTkFrame(left_frame)
        dict_frame.pack(pady=10, fill="x", padx=5)
        
        # 字典类型选择
        self.subdomain_dict_var = ctk.StringVar(value="内置字典")
        dict_label = ctk.CTkLabel(dict_frame, text="字典类型:", font=("微软雅黑", 12))
        dict_label.pack(pady=5)
        dict_options = ["内置字典", "自定义字典"]
        self.subdomain_dict_menu = ctk.CTkOptionMenu(dict_frame, values=dict_options, 
                                                    variable=self.subdomain_dict_var, 
                                                    command=self.on_subdomain_dict_change)
        self.subdomain_dict_menu.pack(pady=5)
        
        # 内置字典选择
        self.subdomain_builtin_frame = ctk.CTkFrame(left_frame)
        self.subdomain_builtin_frame.pack(pady=5, fill="x", padx=5)
        
        self.subdomain_builtin_var = ctk.StringVar(value="常用子域名")
        builtin_options = ["常用子域名", "短子域名", "完整子域名"]
        self.subdomain_builtin_menu = ctk.CTkOptionMenu(self.subdomain_builtin_frame, 
                                                       values=builtin_options, 
                                                       variable=self.subdomain_builtin_var)
        self.subdomain_builtin_menu.pack(pady=5)
        
        # 自定义字典框架
        self.subdomain_custom_frame = ctk.CTkFrame(left_frame)
        
        # 文件选择按钮
        self.subdomain_select_file_button = ctk.CTkButton(self.subdomain_custom_frame, 
                                                         text="选择字典文件", 
                                                         command=self.select_subdomain_file)
        self.subdomain_select_file_button.pack(pady=5)
        
        # 显示选中的文件路径
        self.subdomain_file_path_label = ctk.CTkLabel(self.subdomain_custom_frame, 
                                                     text="未选择文件", 
                                                     font=("微软雅黑", 10))
        self.subdomain_file_path_label.pack(pady=5)
        
        # 或者手动输入
        self.subdomain_custom_label = ctk.CTkLabel(self.subdomain_custom_frame, 
                                                  text="或直接输入子域名\n(每行一个)", 
                                                  font=("微软雅黑", 10))
        self.subdomain_custom_label.pack(pady=5)
        
        self.subdomain_custom_text = ctk.CTkTextbox(self.subdomain_custom_frame, height=200)
        self.subdomain_custom_text.pack(pady=5, fill="both", expand=True, padx=5)
        
        # DNS服务器设置
        dns_frame = ctk.CTkFrame(left_frame)
        dns_frame.pack(fill="x", pady=5, padx=5)
        
        dns_label = ctk.CTkLabel(dns_frame, text="DNS服务器:", font=("微软雅黑", 12))
        dns_label.pack(side="left", padx=5)
        
        self.dns_server_var = ctk.StringVar(value="8.8.8.8")
        dns_options = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "114.114.114.114"]
        self.dns_server_menu = ctk.CTkOptionMenu(dns_frame, values=dns_options, 
                                                variable=self.dns_server_var)
        self.dns_server_menu.pack(side="left", padx=5)
        
        # 线程数选择
        thread_label = ctk.CTkLabel(left_frame, text="扫描线程数:", font=("微软雅黑", 12))
        thread_label.pack(pady=5)
        self.subdomain_thread_slider = ctk.CTkSlider(left_frame, from_=1, to=50, number_of_steps=49)
        self.subdomain_thread_slider.pack(pady=5)
        self.subdomain_thread_slider.set(10)
        
        # 超时设置
        timeout_label = ctk.CTkLabel(left_frame, text="DNS超时(秒):", font=("微软雅黑", 12))
        timeout_label.pack(pady=5)
        self.subdomain_timeout_slider = ctk.CTkSlider(left_frame, from_=1, to=10.0, number_of_steps=90)
        self.subdomain_timeout_slider.pack(pady=5)
        self.subdomain_timeout_slider.set(3.0)
        
        # 控制按钮
        self.subdomain_start_button = ctk.CTkButton(left_frame, text="开始扫描", 
                                                   command=self.start_subdomain_scan)
        self.subdomain_start_button.pack(pady=10)
        
        self.subdomain_stop_button = ctk.CTkButton(left_frame, text="停止扫描", 
                                                  command=self.stop_scanning, state="disabled")
        self.subdomain_stop_button.pack(pady=5)
        
        # 创建右侧结果显示区域
        right_frame = ctk.CTkFrame(self.subdomain_tab)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # 进度条
        self.subdomain_progress_var = ctk.DoubleVar()
        self.subdomain_progress_bar = ctk.CTkProgressBar(right_frame)
        self.subdomain_progress_bar.pack(fill="x", padx=10, pady=5)
        self.subdomain_progress_bar.set(0)
        
        # 状态标签
        self.subdomain_status_label = ctk.CTkLabel(right_frame, text="就绪", font=("微软雅黑", 12))
        self.subdomain_status_label.pack(pady=5)
        
        # 结果表格
        columns = ("子域名", "IP地址", "状态")
        self.subdomain_result_tree = ttk.Treeview(right_frame, columns=columns, show="headings")
        
        # 设置列标题
        for col in columns:
            self.subdomain_result_tree.heading(col, text=col)
            self.subdomain_result_tree.column(col, width=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(right_frame, orient="vertical", 
                                command=self.subdomain_result_tree.yview)
        self.subdomain_result_tree.configure(yscrollcommand=scrollbar.set)
        
        self.subdomain_result_tree.pack(fill="both", expand=True, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # 初始化显示内置字典框架
        self.on_subdomain_dict_change("内置字典")

    def on_subdomain_dict_change(self, choice):
        if choice == "内置字典":
            self.subdomain_custom_frame.pack_forget()
            self.subdomain_builtin_frame.pack(pady=5, fill="x", padx=5)
        else:
            self.subdomain_builtin_frame.pack_forget()
            self.subdomain_custom_frame.pack(pady=5, fill="x", padx=5)

    def select_subdomain_file(self):
        file_path = filedialog.askopenfilename(
            title="选择子域名字典文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            self.subdomain_file_path_label.configure(text=file_path)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.subdomain_custom_text.delete("0.0", "end")
                    self.subdomain_custom_text.insert("0.0", content)
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败: {str(e)}")

    def get_subdomain_list(self):
        if self.subdomain_dict_var.get() == "内置字典":
            # 内置字典
            common_subdomains = ["www", "mail", "ftp", "smtp", "pop", "m", "webmail", 
                               "pop3", "imap", "localhost", "autodiscover", "admin",
                               "blog", "wap", "dev", "api", "ws", "cp", "shop", "store",
                               "download", "downloads", "web", "direct", "remote", "cdn",
                               "apps", "app", "proxy", "ps", "ssl", "vpn", "dns", "ts",
                               "support", "portal", "beta", "demo", "status", "static"]
                               
            short_subdomains = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
                               "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
                               "w", "x", "y", "z", "1", "2", "3", "4", "5", "6", "7",
                               "8", "9", "0"]
                               
            full_subdomains = common_subdomains + short_subdomains + [
                "forum", "bbs", "news", "home", "mysql", "ftp1", "ftp2", "ns", "ns1",
                "ns2", "ns3", "ns4", "ns5", "video", "img", "images", "cloud", "office",
                "help", "service", "services", "stats", "statistics", "host", "hosting",
                "server", "servers", "backup", "git", "svn", "tfs", "test", "testing",
                "development", "developer", "developers", "ww1", "ww2", "ww3", "www1",
                "www2", "www3", "wwww", "w", "intranet", "internal", "external", "extra",
                "extranet", "members", "member", "client", "clients", "customer",
                "customers", "sql", "db", "database", "databases", "oracle", "cisco",
                "citrix", "ads", "ad", "auth", "authentication"
            ]

            dict_type = self.subdomain_builtin_var.get()
            if dict_type == "短子域名":
                return short_subdomains
            elif dict_type == "完整子域名":
                return full_subdomains
            else:
                return common_subdomains
        else:
            # 自定义字典
            custom_content = self.subdomain_custom_text.get("0.0", "end").strip()
            if not custom_content:
                messagebox.showwarning("警告", "自定义字典为空，请输入子域名或选择字典文件")
                return []
            return [line.strip() for line in custom_content.split('\n') if line.strip()]

    def scan_subdomain(self, domain, subdomain, timeout):
        try:
            full_domain = f"{subdomain}.{domain}"
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server_var.get()]
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            answers = resolver.resolve(full_domain, 'A')
            ip_addresses = [rdata.address for rdata in answers]
            
            # 尝试HTTP连接
            try:
                response = requests.get(f"http://{full_domain}", timeout=timeout, 
                                     allow_redirects=False)
                status = f"HTTP {response.status_code}"
            except:
                try:
                    response = requests.get(f"https://{full_domain}", timeout=timeout, 
                                         allow_redirects=False, verify=False)
                    status = f"HTTPS {response.status_code}"
                except:
                    status = "DNS Only"
            
            self.result_queue.put(("subdomain", full_domain, ", ".join(ip_addresses), status))
            return True
        except:
            return False

    def start_subdomain_scan(self):
        # 清空之前的结果
        for item in self.subdomain_result_tree.get_children():
            self.subdomain_result_tree.delete(item)
            
        self.subdomain_start_button.configure(state="disabled")
        self.subdomain_stop_button.configure(state="normal")
        self.subdomain_progress_bar.set(0)
        
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("错误", "请输入目标域名")
            return
            
        timeout = self.subdomain_timeout_slider.get()
        subdomains = self.get_subdomain_list()
        
        def run_scan():
            total = len(subdomains)
            scanned = 0
            
            for subdomain in subdomains:
                if self.stop_scan:
                    break
                    
                self.scan_subdomain(domain, subdomain, timeout)
                scanned += 1
                progress = scanned / total
                self.subdomain_progress_var.set(progress)
                self.subdomain_progress_bar.set(progress)
                
                # 更新状态
                self.subdomain_status_label.configure(text=f"正在扫描 {scanned}/{total}")
            
            if not self.stop_scan:
                self.subdomain_status_label.configure(text="扫描完成")
            else:
                self.subdomain_status_label.configure(text="扫描已停止")
            
            self.subdomain_start_button.configure(state="normal")
            self.subdomain_stop_button.configure(state="disabled")
            self.stop_scan = False
        
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.update_results()

    def create_ip_trace_widgets(self):
        # 创建左侧面板
        left_frame = ctk.CTkFrame(self.ip_trace_tab)
        left_frame.pack(side="left", fill="y", padx=10, pady=10)
        
        # IP输入
        ip_label = ctk.CTkLabel(left_frame, text="目标IP地址:", font=("微软雅黑", 12))
        ip_label.pack(pady=5)
        self.trace_ip_entry = ctk.CTkEntry(left_frame, width=200)
        self.trace_ip_entry.pack(pady=5)
        self.trace_ip_entry.insert(0, "8.8.8.8")
        
        # 查询按钮
        self.trace_button = ctk.CTkButton(left_frame, text="查询位置", command=self.trace_ip_location)
        self.trace_button.pack(pady=10)
        
        # 创建右侧结果显示区域
        right_frame = ctk.CTkFrame(self.ip_trace_tab)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # 结果显示
        self.trace_result_text = ctk.CTkTextbox(right_frame, font=("Consolas", 12))
        self.trace_result_text.pack(fill="both", expand=True, pady=5)

    def trace_ip_location(self):
        ip = self.trace_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("错误", "请输入有效的IP地址")
            return
        
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            data = response.json()
            
            # 格式化输出结果
            output = f"IP地址: {data.get('ip', '未知')}\n"
            output += f"国家: {data.get('country', '未知')}\n"
            output += f"地区: {data.get('region', '未知')}\n"
            output += f"城市: {data.get('city', '未知')}\n"
            output += f"组织: {data.get('org', '未知')}\n"
            output += f"位置: {data.get('loc', '未知')}\n"
            
            self.trace_result_text.delete("0.0", "end")
            self.trace_result_text.insert("0.0", output)
        except Exception as e:
            messagebox.showerror("错误", f"查询失败: {str(e)}")

    def create_code_audit_widgets(self):
        # 创建左侧面板
        left_frame = ctk.CTkFrame(self.code_audit_tab)
        left_frame.pack(side="left", fill="y", padx=10, pady=10)
        
        # 文件夹选择
        folder_frame = ctk.CTkFrame(left_frame)
        folder_frame.pack(fill="x", pady=5)
        
        self.folder_label = ctk.CTkLabel(folder_frame, text="选择代码目录:", font=("微软雅黑", 12))
        self.folder_label.pack(pady=5)
        
        self.folder_path = ctk.CTkEntry(folder_frame, width=200)
        self.folder_path.pack(pady=5)
        
        self.select_folder_button = ctk.CTkButton(folder_frame, text="浏览", 
                                                command=self.select_code_folder)
        self.select_folder_button.pack(pady=5)

        # 文件列表显示
        files_frame = ctk.CTkFrame(left_frame)
        files_frame.pack(fill="both", expand=True, pady=5)
        
        files_label = ctk.CTkLabel(files_frame, text="文件列表:", font=("微软雅黑", 12))
        files_label.pack(pady=5)
        
        # 创建文件列表树形视图
        self.files_tree = ttk.Treeview(files_frame, show="tree", selectmode="extended")
        self.files_tree.pack(fill="both", expand=True, pady=5)
        
        # 添加滚动条
        files_scroll = ttk.Scrollbar(files_frame, orient="vertical", 
                                   command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=files_scroll.set)
        files_scroll.pack(side="right", fill="y")
        
        # 文件类型选择
        file_type_frame = ctk.CTkFrame(left_frame)
        file_type_frame.pack(fill="x", pady=10)
        
        file_type_label = ctk.CTkLabel(file_type_frame, text="选择文件类型:", font=("微软雅黑", 12))
        file_type_label.pack(pady=5)
        
        self.file_types = {
            "PHP": ".php",
            "Java": ".java",
            "ASP": ".asp",
            "JavaScript": ".js"
        }
        
        self.file_type_vars = {}
        for file_type in self.file_types:
            var = ctk.BooleanVar(value=True)
            self.file_type_vars[file_type] = var
            checkbox = ctk.CTkCheckBox(file_type_frame, text=file_type, 
                                     variable=var, command=self.update_file_list)
            checkbox.pack(pady=2)
        
        # AI设置
        ai_frame = ctk.CTkFrame(left_frame)
        ai_frame.pack(fill="x", pady=10)
        
        ai_label = ctk.CTkLabel(ai_frame, text="AI设置:", font=("微软雅黑", 12))
        ai_label.pack(pady=5)
        
        # AI选择
        self.ai_var = ctk.StringVar(value="ChatGPT")
        ai_options = ["ChatGPT", "Gemini", "Claude", "DeepSeek", "Kimi"]  # 添加Kimi选项
        self.ai_menu = ctk.CTkOptionMenu(ai_frame, values=ai_options, variable=self.ai_var)
        self.ai_menu.pack(pady=5)
        
        # API密钥设置按钮
        self.api_key_button = ctk.CTkButton(ai_frame, text="设置API密钥", 
                                          command=self.show_api_key_dialog)
        self.api_key_button.pack(pady=5)
        
        # 控制按钮
        self.audit_start_button = ctk.CTkButton(left_frame, text="开始审计", 
                                              command=self.start_code_audit)
        self.audit_start_button.pack(pady=10)
        
        self.audit_stop_button = ctk.CTkButton(left_frame, text="停止审计", 
                                             command=self.stop_scanning, state="disabled")
        self.audit_stop_button.pack(pady=5)
        
        # 创建右侧结果显示区域
        right_frame = ctk.CTkFrame(self.code_audit_tab)
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # 进度条
        self.audit_progress_var = ctk.DoubleVar()
        self.audit_progress_bar = ctk.CTkProgressBar(right_frame)
        self.audit_progress_bar.pack(fill="x", padx=10, pady=5)
        self.audit_progress_bar.set(0)
        
        # 状态标签
        self.audit_status_label = ctk.CTkLabel(right_frame, text="就绪", font=("微软雅黑", 12))
        self.audit_status_label.pack(pady=5)
        
        # 结果显示（使用Treeview和Text组合）
        self.audit_result_frame = ctk.CTkFrame(right_frame)
        self.audit_result_frame.pack(fill="both", expand=True, pady=5)
        
        # 创建结果树形视图
        columns = ("文件", "类型", "行号", "漏洞等级", "漏洞描述")
        self.audit_result_tree = ttk.Treeview(self.audit_result_frame, 
                                            columns=columns, show="headings")
        
        # 设置列标题和宽度
        self.audit_result_tree.heading("文件", text="文件")
        self.audit_result_tree.heading("类型", text="类型")
        self.audit_result_tree.heading("行号", text="行号")
        self.audit_result_tree.heading("漏洞等级", text="漏洞等级")
        self.audit_result_tree.heading("漏洞描述", text="漏洞描述")
        
        # 设置列宽
        self.audit_result_tree.column("文件", width=200)
        self.audit_result_tree.column("类型", width=80)
        self.audit_result_tree.column("行号", width=60)
        self.audit_result_tree.column("漏洞等级", width=80)
        self.audit_result_tree.column("漏洞描述", width=300)
        
        # 添加滚动条
        tree_scroll = ttk.Scrollbar(self.audit_result_frame, orient="vertical", 
                                  command=self.audit_result_tree.yview)
        self.audit_result_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.audit_result_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        
        # 详细信息显示
        self.detail_frame = ctk.CTkFrame(right_frame)
        self.detail_frame.pack(fill="both", expand=True, pady=5)
        
        detail_label = ctk.CTkLabel(self.detail_frame, text="漏洞详情:", font=("微软雅黑", 12))
        detail_label.pack(pady=5)
        
        self.detail_text = ctk.CTkTextbox(self.detail_frame, height=200)
        self.detail_text.pack(fill="both", expand=True, pady=5)
        
        # 绑定树形视图选择事件
        self.audit_result_tree.bind('<<TreeviewSelect>>', self.show_vulnerability_detail)

    def select_code_folder(self):
        folder_path = filedialog.askdirectory(title="选择代码目录")
        if folder_path:
            self.folder_path.delete(0, "end")
            self.folder_path.insert(0, folder_path)
            self.update_file_list()

    def update_file_list(self):
        folder_path = self.folder_path.get()
        if not folder_path or not os.path.exists(folder_path):
            return
            
        # 清空当前文件列表
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
            
        # 获取选中的文件类型
        selected_extensions = []
        for file_type, var in self.file_type_vars.items():
            if var.get():
                selected_extensions.append(self.file_types[file_type])
        
        # 添加文件到树形视图
        for root, dirs, files in os.walk(folder_path):
            # 创建相对路径
            rel_path = os.path.relpath(root, folder_path)
            if rel_path == ".":
                parent = ""
            else:
                # 确保父目录已创建
                parent_path = os.path.dirname(rel_path)
                if parent_path:
                    parent = parent_path.replace(os.sep, "/")
                else:
                    parent = ""
                
                # 创建当前目录节点
                dir_name = os.path.basename(rel_path)
                dir_id = rel_path.replace(os.sep, "/")
                if not self.files_tree.exists(dir_id):
                    self.files_tree.insert(parent, "end", dir_id, text=dir_name)
            
            # 添加文件
            for file in files:
                file_ext = os.path.splitext(file)[1].lower()
                if file_ext in selected_extensions:
                    file_path = os.path.join(rel_path, file).replace(os.sep, "/")
                    if rel_path == ".":
                        self.files_tree.insert("", "end", file_path, text=file)
                    else:
                        self.files_tree.insert(rel_path.replace(os.sep, "/"), "end", file_path, text=file)

    def show_api_key_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("设置API密钥和地址")
        dialog.geometry("600x400")
        
        # 创建滚动框架
        canvas = ctk.CTkCanvas(dialog)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ctk.CTkFrame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # 为每个AI服务创建输入框
        entries = {}
        url_entries = {}
        
        for i, (service, key) in enumerate(self.ai_api_keys.items()):
            # API密钥设置
            key_frame = ctk.CTkFrame(scrollable_frame)
            key_frame.pack(fill="x", padx=20, pady=5)
            
            key_label = ctk.CTkLabel(key_frame, text=f"{service} API密钥:")
            key_label.pack(side="left", padx=5)
            
            key_entry = ctk.CTkEntry(key_frame, width=300, show="*")
            key_entry.pack(side="left", padx=5)
            key_entry.insert(0, key)
            entries[service] = key_entry
            
            # API地址设置
            url_frame = ctk.CTkFrame(scrollable_frame)
            url_frame.pack(fill="x", padx=20, pady=5)
            
            url_label = ctk.CTkLabel(url_frame, text=f"{service} API地址:")
            url_label.pack(side="left", padx=5)
            
            url_entry = ctk.CTkEntry(url_frame, width=300)
            url_entry.pack(side="left", padx=5)
            url_entry.insert(0, self.ai_api_urls.get(service, ""))
            url_entries[service] = url_entry
        
        def save_settings():
            for service, entry in entries.items():
                self.ai_api_keys[service] = entry.get()
            for service, entry in url_entries.items():
                self.ai_api_urls[service] = entry.get()
            dialog.destroy()
            messagebox.showinfo("成功", "API设置已保存")
        
        save_button = ctk.CTkButton(scrollable_frame, text="保存", command=save_settings)
        save_button.pack(pady=20)
        
        # 打包滚动组件
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def analyze_code_with_ai(self, code, file_type):
        selected_ai = self.ai_var.get()
        try:
            if selected_ai == "ChatGPT":
                if not self.ai_api_keys['openai']:
                    raise ValueError("请先设置OpenAI API密钥")
                    
                client = OpenAI(
                    api_key=self.ai_api_keys['openai'],
                    base_url=self.ai_api_urls['openai']
                )
                
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "你是一个专业的代码安全审计专家，请分析以下代码中的安全漏洞，并提供详细的漏洞利用方法。"},
                        {"role": "user", "content": f"""分析以下{file_type}代码的安全漏洞，并按以下格式输出:
1. 漏洞类型
2. 漏洞描述
3. 漏洞危害
4. 利用方法
5. 修复建议

代码内容:
{code}"""}
                    ]
                )
                return response.choices[0].message.content
                
            elif selected_ai == "Gemini":
                if not self.ai_api_keys['gemini']:
                    raise ValueError("请先设置Gemini API密钥")
                    
                genai.configure(api_key=self.ai_api_keys['gemini'])
                model = genai.GenerativeModel('gemini-pro')
                response = model.generate_content(
                    f"""作为代码安全审计专家，分析以下{file_type}代码的安全漏洞，并按以下格式输出:
1. 漏洞类型
2. 漏洞描述
3. 漏洞危害
4. 利用方法
5. 修复建议

代码内容:
{code}"""
                )
                return response.text
                
            elif selected_ai == "Claude":
                if not self.ai_api_keys['anthropic']:
                    raise ValueError("请先设置Anthropic API密钥")
                    
                client = Anthropic(api_key=self.ai_api_keys['anthropic'])
                message = client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=4096,
                    messages=[{
                        "role": "user",
                        "content": f"""作为代码安全审计专家，分析以下{file_type}代码的安全漏洞，并按以下格式输出:
1. 漏洞类型
2. 漏洞描述
3. 漏洞危害
4. 利用方法
5. 修复建议

代码内容:
{code}"""
                    }]
                )
                return message.content[0].text
                
            elif selected_ai == "DeepSeek":
                if not self.ai_api_keys['deepseek']:
                    raise ValueError("请先设置DeepSeek API密钥")
                    
                client = OpenAI(
                    api_key=self.ai_api_keys['deepseek'],
                    base_url="https://api.deepseek.com/v1"
                )
                
                response = client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": "你是一个专业的代码安全审计专家，请分析以下代码中的安全漏洞，并提供详细的漏洞利用方法。"},
                        {"role": "user", "content": f"""分析以下{file_type}代码的安全漏洞，并按以下格式输出:
1. 漏洞类型
2. 漏洞描述
3. 漏洞危害
4. 利用方法
5. 修复建议

代码内容:
{code}"""}
                    ]
                )
                return response.choices[0].message.content
                
            elif selected_ai == "Kimi":
                if not self.ai_api_keys['kimi']:
                    raise ValueError("请先设置Kimi API密钥")
                    
                client = OpenAI(
                    api_key=self.ai_api_keys['kimi'],
                    base_url="https://api.moonshot.cn/v1"
                )
                
                response = client.chat.completions.create(
                    model="moonshot-v1-8k",
                    messages=[
                        {"role": "system", "content": "你是一个专业的代码安全审计专家，请分析以下代码中的安全漏洞，并提供详细的漏洞利用方法。"},
                        {"role": "user", "content": f"""分析以下{file_type}代码的安全漏洞，并按以下格式输出:
1. 漏洞类型
2. 漏洞描述
3. 漏洞危害
4. 利用方法
5. 修复建议

代码内容:
{code}"""}
                    ]
                )
                return response.choices[0].message.content
                
        except Exception as e:
            return f"AI分析失败: {str(e)}"

    def analyze_php_code(self, file_path):
        vulnerabilities = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
                
            # 常见PHP漏洞模式
            patterns = {
                'SQL注入': r'mysql_query\s*\(\s*\$[^,)]*\)',
                '命令执行': r'(system|exec|shell_exec|passthru)\s*\([^)]*\$[^)]*\)',
                '文件包含': r'(include|require|include_once|require_once)\s*\([^)]*\$[^)]*\)',
                'XSS': r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
                '文件操作': r'(fopen|file_get_contents|file_put_contents)\s*\([^)]*\$[^)]*\)'
            }
            
            for vuln_type, pattern in patterns.items():
                matches = re.finditer(pattern, code)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    vulnerabilities.append({
                        'file': file_path,
                        'type': 'PHP',
                        'line': line_number,
                        'level': '高危',
                        'description': f'发现潜在的{vuln_type}漏洞',
                        'code': match.group()
                    })
            
            # 使用AI进行深度分析
            ai_analysis = self.analyze_code_with_ai(code, 'PHP')
            if ai_analysis:
                vulnerabilities.append({
                    'file': file_path,
                    'type': 'PHP',
                    'line': 0,
                    'level': '待确认',
                    'description': 'AI分析结果',
                    'code': ai_analysis
                })
                
        except Exception as e:
            vulnerabilities.append({
                'file': file_path,
                'type': 'PHP',
                'line': 0,
                'level': '错误',
                'description': f'分析失败: {str(e)}',
                'code': ''
            })
            
        return vulnerabilities

    def analyze_java_code(self, file_path):
        vulnerabilities = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
                
            # 常见Java漏洞模式
            patterns = {
                'SQL注入': r'Statement\s*\.\s*execute\s*\([^)]*\+',
                '命令执行': r'Runtime\s*\.\s*exec\s*\([^)]*\)',
                '反序列化': r'ObjectInputStream|readObject\s*\(',
                'XSS': r'response\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*print',
                '文件操作': r'new\s+File\s*\([^)]*\)'
            }
            
            for vuln_type, pattern in patterns.items():
                matches = re.finditer(pattern, code)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    vulnerabilities.append({
                        'file': file_path,
                        'type': 'Java',
                        'line': line_number,
                        'level': '高危',
                        'description': f'发现潜在的{vuln_type}漏洞',
                        'code': match.group()
                    })
            
            # 使用AI进行深度分析
            ai_analysis = self.analyze_code_with_ai(code, 'Java')
            if ai_analysis:
                vulnerabilities.append({
                    'file': file_path,
                    'type': 'Java',
                    'line': 0,
                    'level': '待确认',
                    'description': 'AI分析结果',
                    'code': ai_analysis
                })
                
        except Exception as e:
            vulnerabilities.append({
                'file': file_path,
                'type': 'Java',
                'line': 0,
                'level': '错误',
                'description': f'分析失败: {str(e)}',
                'code': ''
            })
            
        return vulnerabilities

    def analyze_asp_code(self, file_path):
        vulnerabilities = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
                
            # 常见ASP漏洞模式
            patterns = {
                'SQL注入': r'Execute\s*\([^)]*Request',
                '命令执行': r'wscript.shell|Shell.Application',
                'XSS': r'Response.Write\s*\([^)]*Request',
                '文件操作': r'FileSystemObject|SaveAs|CreateTextFile'
            }
            
            for vuln_type, pattern in patterns.items():
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    vulnerabilities.append({
                        'file': file_path,
                        'type': 'ASP',
                        'line': line_number,
                        'level': '高危',
                        'description': f'发现潜在的{vuln_type}漏洞',
                        'code': match.group()
                    })
            
            # 使用AI进行深度分析
            ai_analysis = self.analyze_code_with_ai(code, 'ASP')
            if ai_analysis:
                vulnerabilities.append({
                    'file': file_path,
                    'type': 'ASP',
                    'line': 0,
                    'level': '待确认',
                    'description': 'AI分析结果',
                    'code': ai_analysis
                })
                
        except Exception as e:
            vulnerabilities.append({
                'file': file_path,
                'type': 'ASP',
                'line': 0,
                'level': '错误',
                'description': f'分析失败: {str(e)}',
                'code': ''
            })
            
        return vulnerabilities

    def analyze_js_code(self, file_path):
        vulnerabilities = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
                
            # 常见JavaScript漏洞模式
            patterns = {
                'XSS': r'innerHTML|document\.write',
                '命令执行': r'eval\s*\([^)]*\)',
                '不安全的JSON解析': r'JSON\.parse\s*\([^)]*\)',
                'DOM操作': r'getElementById|querySelector',
                '敏感信息': r'localStorage|sessionStorage'
            }
            
            for vuln_type, pattern in patterns.items():
                matches = re.finditer(pattern, code)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    vulnerabilities.append({
                        'file': file_path,
                        'type': 'JavaScript',
                        'line': line_number,
                        'level': '中危',
                        'description': f'发现潜在的{vuln_type}漏洞',
                        'code': match.group()
                    })
            
            # 使用AI进行深度分析
            ai_analysis = self.analyze_code_with_ai(code, 'JavaScript')
            if ai_analysis:
                vulnerabilities.append({
                    'file': file_path,
                    'type': 'JavaScript',
                    'line': 0,
                    'level': '待确认',
                    'description': 'AI分析结果',
                    'code': ai_analysis
                })
                
        except Exception as e:
            vulnerabilities.append({
                'file': file_path,
                'type': 'JavaScript',
                'line': 0,
                'level': '错误',
                'description': f'分析失败: {str(e)}',
                'code': ''
            })
            
        return vulnerabilities

    def start_code_audit(self):
        # 获取选中的文件
        selected_items = self.files_tree.selection()
        if not selected_items:
            messagebox.showerror("错误", "请选择要审计的文件")
            return
            
        folder_path = self.folder_path.get()
        if not folder_path or not os.path.exists(folder_path):
            messagebox.showerror("错误", "请选择有效的代码目录")
            return
            
        # 清空之前的结果
        for item in self.audit_result_tree.get_children():
            self.audit_result_tree.delete(item)
        self.detail_text.delete("0.0", "end")
        
        # 更新界面状态
        self.audit_start_button.configure(state="disabled")
        self.audit_stop_button.configure(state="normal")
        self.audit_progress_bar.set(0)
        
        def run_audit():
            total_files = len(selected_items)
            processed_files = 0
            
            for item_id in selected_items:
                if self.stop_scan:
                    break
                    
                file_path = os.path.join(folder_path, item_id)
                file_ext = os.path.splitext(file_path)[1].lower()
                
                # 根据文件类型选择相应的分析方法
                if file_ext == '.php':
                    vulnerabilities = self.analyze_php_code(file_path)
                elif file_ext == '.java':
                    vulnerabilities = self.analyze_java_code(file_path)
                elif file_ext == '.asp':
                    vulnerabilities = self.analyze_asp_code(file_path)
                elif file_ext == '.js':
                    vulnerabilities = self.analyze_js_code(file_path)
                
                # 更新结果
                for vuln in vulnerabilities:
                    self.result_queue.put(("audit", vuln))
                
                processed_files += 1
                progress = processed_files / total_files
                self.audit_progress_var.set(progress)
                self.audit_progress_bar.set(progress)
                
                # 更新状态
                self.audit_status_label.configure(
                    text=f"正在扫描: {processed_files}/{total_files}"
                )
            
            if not self.stop_scan:
                self.audit_status_label.configure(text="扫描完成")
            else:
                self.audit_status_label.configure(text="扫描已停止")
                
            self.audit_start_button.configure(state="normal")
            self.audit_stop_button.configure(state="disabled")
            self.stop_scan = False
        
        self.scan_thread = threading.Thread(target=run_audit)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.update_results()

    def show_vulnerability_detail(self, event):
        selection = self.audit_result_tree.selection()
        if not selection:
            return
            
        item = self.audit_result_tree.item(selection[0])
        values = item['values']
        
        # 清空详情文本框
        self.detail_text.delete("0.0", "end")
        
        # 显示详细信息
        detail = f"文件: {values[0]}\n"
        detail += f"类型: {values[1]}\n"
        detail += f"行号: {values[2]}\n"
        detail += f"等级: {values[3]}\n"
        detail += f"描述: {values[4]}\n\n"
        
        # 如果有代码片段，显示代码
        if len(values) > 5:
            detail += "相关代码:\n"
            detail += values[5]
        
        self.detail_text.insert("0.0", detail)

if __name__ == "__main__":
    app = Scanner()
    app.mainloop() 
