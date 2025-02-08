import customtkinter as ctk
import threading
import socket
import queue
import time
import requests
import json
import dns.resolver
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
from urllib.parse import urljoin, urlparse

class Scanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # 设置主题和外观
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # 配置窗口
        self.title("通用扫描器")
        self.geometry("800x600")
        self.minsize(800, 600)
        
        # 初始化变量
        self.scan_thread = None
        self.stop_scan = False
        self.result_queue = queue.Queue()
        
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
        
        # 创建各个界面
        self.create_port_scan_widgets()
        self.create_dir_scan_widgets()
        self.create_subdomain_scan_widgets()
        self.create_poc_test_widgets()
        self.create_ip_trace_widgets()
        
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

if __name__ == "__main__":
    app = Scanner()
    app.mainloop() 