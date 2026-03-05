import sys
import random
import time
import json
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QPushButton, QLabel, 
                             QLineEdit, QComboBox, QProgressBar, QGroupBox,
                             QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
                             QSpinBox, QCheckBox, QTabWidget, QMessageBox, QSplitter,
                             QStatusBar, QMenuBar, QMenu, QDialog, QDialogButtonBox,
                             QRadioButton, QButtonGroup, QSlider, QSystemTrayIcon)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer, QSettings
from PyQt6.QtGui import QColor, QFont, QAction, QIcon
import requests
from urllib.parse import urlparse, quote
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


class ProxyTester(QThread):
    """Thread for testing proxies with concurrent execution"""
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    log_message = pyqtSignal(str)
    
    def __init__(self, proxies, test_urls, timeout, max_workers=10, test_types=None):
        super().__init__()
        self.proxies = proxies
        self.test_urls = test_urls if isinstance(test_urls, list) else [test_urls]
        self.timeout = timeout
        self.max_workers = max_workers
        self.is_running = True
        self.test_types = test_types or ['http', 'https', 'socks4', 'socks5']
        self.total_tested = 0
        
    def stop(self):
        self.is_running = False
        
    def get_realistic_headers(self):
        """Generate realistic browser headers with more variety"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
        ]
        
        accept_languages = [
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'en-US,en;q=0.9,es;q=0.8',
            'en-US,en;q=0.9,fr;q=0.8',
            'en-US,en;q=0.9,de;q=0.8',
        ]
        
        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': random.choice(accept_languages),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'Referer': 'https://www.google.com/',
        }
        
        return headers
    
    def simulate_browsing_behavior(self):
        """Add realistic delays"""
        time.sleep(random.uniform(0.2, 1.0))
    
    def detect_proxy_type(self, proxy_string):
        """Detect proxy type from string format"""
        if proxy_string.startswith('socks5://'):
            return 'socks5'
        elif proxy_string.startswith('socks4://'):
            return 'socks4'
        elif proxy_string.startswith('https://'):
            return 'https'
        elif proxy_string.startswith('http://'):
            return 'http'
        return 'http'  # Default
    
    def test_proxy(self, proxy_string):
        """Test a single proxy with comprehensive checks"""
        result = {
            'proxy': proxy_string,
            'status': 'Failed',
            'response_time': 'N/A',
            'ip': 'N/A',
            'location': 'N/A',
            'anonymity': 'N/A',
            'protocol': 'N/A',
            'error': '',
            'speed_score': 0,
            'working_urls': 0
        }
        
        try:
            # Parse proxy string
            proxy_type = self.detect_proxy_type(proxy_string)
            proxy_clean = proxy_string.replace('socks5://', '').replace('socks4://', '').replace('https://', '').replace('http://', '')
            proxy_parts = proxy_clean.strip().split(':')
            
            if len(proxy_parts) < 2:
                result['error'] = 'Invalid proxy format'
                return result
            
            proxy_host = proxy_parts[0]
            proxy_port = proxy_parts[1]
            
            # Support authentication
            if len(proxy_parts) == 4:
                proxy_user = quote(proxy_parts[2], safe="")
                proxy_pass = quote(proxy_parts[3], safe="")
                proxy_url = f"{proxy_type}://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
            else:
                proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"
            
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            result['protocol'] = proxy_type.upper()
            
            # Simulate browsing behavior
            if not self.is_running:
                return result
            
            self.simulate_browsing_behavior()
            
            # Get realistic headers
            headers = self.get_realistic_headers()
            
            # Test the proxy against multiple URLs
            session = requests.Session()
            session.headers.update(headers)
            
            total_time = 0
            successful_tests = 0
            
            for test_url in self.test_urls:
                if not self.is_running:
                    break
                    
                try:
                    start_time = time.time()
                    response = session.get(
                        test_url,
                        proxies=proxies,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=True
                    )
                    end_time = time.time()
                    
                    if response.status_code == 200:
                        successful_tests += 1
                        total_time += (end_time - start_time)
                except:
                    pass
            
            result['working_urls'] = successful_tests
            
            if successful_tests > 0:
                avg_response_time = (total_time / successful_tests) * 1000
                result['status'] = 'Working'
                result['response_time'] = f"{round(avg_response_time, 2)}ms"
                
                # Calculate speed score (0-100)
                if avg_response_time < 500:
                    result['speed_score'] = 100
                elif avg_response_time < 1000:
                    result['speed_score'] = 80
                elif avg_response_time < 2000:
                    result['speed_score'] = 60
                elif avg_response_time < 5000:
                    result['speed_score'] = 40
                else:
                    result['speed_score'] = 20
                
                # Try to get IP and location info
                try:
                    ip_response = session.get(
                        'https://api.ipify.org?format=json',
                        proxies=proxies,
                        timeout=self.timeout
                    )
                    if ip_response.status_code == 200:
                        result['ip'] = ip_response.json().get('ip', 'N/A')
                        
                        # Check anonymity
                        anonymity_response = session.get(
                            'https://httpbin.org/headers',
                            proxies=proxies,
                            timeout=self.timeout
                        )
                        if anonymity_response.status_code == 200:
                            response_headers = anonymity_response.json().get('headers', {})
                            if 'X-Forwarded-For' in response_headers or 'Via' in response_headers:
                                result['anonymity'] = 'Transparent'
                            elif 'X-Real-Ip' in response_headers:
                                result['anonymity'] = 'Anonymous'
                            else:
                                result['anonymity'] = 'Elite'
                        
                        # Get location
                        time.sleep(0.5)  # Rate limiting
                        location_response = session.get(
                            f"http://ip-api.com/json/{result['ip']}",
                            timeout=self.timeout
                        )
                        if location_response.status_code == 200:
                            loc_data = location_response.json()
                            country = loc_data.get('country', '')
                            city = loc_data.get('city', '')
                            isp = loc_data.get('isp', '')
                            result['location'] = f"{city}, {country}" if city else country
                            if isp:
                                result['location'] += f" ({isp})"
                except Exception as e:
                    pass
            else:
                result['error'] = 'Failed all test URLs'
                
        except requests.exceptions.ProxyError:
            result['error'] = 'Proxy connection failed'
        except requests.exceptions.Timeout:
            result['error'] = 'Connection timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection error'
        except requests.exceptions.SSLError:
            result['error'] = 'SSL certificate error'
        except Exception as e:
            result['error'] = str(e)[:50]
        
        return result
    
    def run(self):
        """Run the proxy testing process with concurrent execution"""
        total = len(self.proxies)
        self.log_message.emit(f"Starting test of {total} proxies with {self.max_workers} concurrent threads...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.test_proxy, proxy): proxy for proxy in self.proxies}
            
            for future in as_completed(futures):
                if not self.is_running:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                try:
                    result = future.result()
                    self.result.emit(result)
                    self.total_tested += 1
                    self.progress.emit(int(self.total_tested / total * 100))
                except Exception as e:
                    self.log_message.emit(f"Error testing proxy: {str(e)}")
        
        self.log_message.emit("Testing completed!")
        self.finished.emit()


class SettingsDialog(QDialog):
    """Dialog for advanced settings"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Advanced Settings")
        self.setModal(True)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Concurrent threads
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Concurrent Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setMinimum(1)
        self.threads_spin.setMaximum(50)
        self.threads_spin.setValue(10)
        threads_layout.addWidget(self.threads_spin)
        layout.addLayout(threads_layout)
        
        # Retry failed proxies
        self.retry_checkbox = QCheckBox("Retry failed proxies once")
        layout.addWidget(self.retry_checkbox)
        
        # Auto-save results
        self.autosave_checkbox = QCheckBox("Auto-save working proxies")
        layout.addWidget(self.autosave_checkbox)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)


class ProxyTesterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Proxy Tester Pro - v2.0")
        self.setGeometry(100, 100, 1400, 900)
        
        self.tester_thread = None
        self.working_proxies = []
        self.failed_proxies = []
        self.test_history = []
        
        # Settings
        self.settings = QSettings("ProxyTesterPro", "Settings")
        self.max_workers = self.settings.value("max_workers", 10, type=int)
        self.auto_save = self.settings.value("auto_save", False, type=bool)
        
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        """Initialize the user interface"""
        # Menu Bar
        self.create_menu_bar()
        
        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Tab Widget
        self.tabs = QTabWidget()
        
        # Testing Tab
        test_tab = QWidget()
        test_layout = QVBoxLayout(test_tab)
        
        # Settings Group
        settings_group = QGroupBox("Test Configuration")
        settings_layout = QVBoxLayout()
        
        # Test URLs (multiple)
        url_layout = QVBoxLayout()
        url_layout.addWidget(QLabel("Test URLs (one per line):"))
        self.url_input = QTextEdit()
        self.url_input.setPlaceholderText("https://httpbin.org/ip\nhttps://api.ipify.org\nhttps://icanhazip.com")
        self.url_input.setText("https://httpbin.org/ip\nhttps://api.ipify.org\nhttps://icanhazip.com")
        self.url_input.setMaximumHeight(80)
        url_layout.addWidget(self.url_input)
        settings_layout.addLayout(url_layout)
        
        # Timeout and threads
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Timeout (sec):"))
        self.timeout_input = QComboBox()
        self.timeout_input.addItems(["5", "10", "15", "20", "30", "45", "60"])
        self.timeout_input.setCurrentText("15")
        control_layout.addWidget(self.timeout_input)
        
        control_layout.addWidget(QLabel("Concurrent Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setMinimum(1)
        self.threads_spin.setMaximum(50)
        self.threads_spin.setValue(self.max_workers)
        control_layout.addWidget(self.threads_spin)
        control_layout.addStretch()
        settings_layout.addLayout(control_layout)
        
        # Protocol selection
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Test Protocols:"))
        self.http_check = QCheckBox("HTTP")
        self.http_check.setChecked(True)
        self.https_check = QCheckBox("HTTPS")
        self.https_check.setChecked(True)
        self.socks4_check = QCheckBox("SOCKS4")
        self.socks5_check = QCheckBox("SOCKS5")
        protocol_layout.addWidget(self.http_check)
        protocol_layout.addWidget(self.https_check)
        protocol_layout.addWidget(self.socks4_check)
        protocol_layout.addWidget(self.socks5_check)
        protocol_layout.addStretch()
        settings_layout.addLayout(protocol_layout)
        
        settings_group.setLayout(settings_layout)
        test_layout.addWidget(settings_group)
        
        # Proxy Input Group
        proxy_group = QGroupBox("Proxy List (Format: host:port or host:port:user:pass)")
        proxy_layout = QVBoxLayout()
        
        # Proxy input toolbar
        proxy_toolbar = QHBoxLayout()
        self.import_button = QPushButton("Import from File")
        self.import_button.clicked.connect(self.import_proxies)
        proxy_toolbar.addWidget(self.import_button)
        
        self.paste_button = QPushButton("Paste from Clipboard")
        self.paste_button.clicked.connect(self.paste_from_clipboard)
        proxy_toolbar.addWidget(self.paste_button)
        
        self.clear_input_button = QPushButton("Clear Input")
        self.clear_input_button.clicked.connect(self.clear_proxy_input)
        proxy_toolbar.addWidget(self.clear_input_button)
        
        proxy_toolbar.addStretch()
        proxy_layout.addLayout(proxy_toolbar)
        
        self.proxy_input = QTextEdit()
        self.proxy_input.setPlaceholderText(
            "Enter proxies (one per line):\n"
            "Examples:\n"
            "123.45.67.89:8080\n"
            "proxy.example.com:3128\n"
            "10.0.0.1:8080:username:password\n"
            "socks5://123.45.67.89:1080\n"
            "http://proxy.example.com:8080"
        )
        self.proxy_input.setMaximumHeight(150)
        proxy_layout.addWidget(self.proxy_input)
        
        # Proxy count label
        self.proxy_count_label = QLabel("Proxies loaded: 0")
        proxy_layout.addWidget(self.proxy_count_label)
        self.proxy_input.textChanged.connect(self.update_proxy_count)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("🚀 Start Testing")
        self.start_button.clicked.connect(self.start_testing)
        self.start_button.setStyleSheet("font-weight: bold; padding: 10px;")
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⏹ Stop")
        self.stop_button.clicked.connect(self.stop_testing)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("padding: 10px;")
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("🗑 Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        self.clear_button.setStyleSheet("padding: 10px;")
        button_layout.addWidget(self.clear_button)
        
        self.export_button = QPushButton("💾 Export Working")
        self.export_button.clicked.connect(self.export_working_proxies)
        self.export_button.setStyleSheet("padding: 10px;")
        button_layout.addWidget(self.export_button)
        
        self.export_all_button = QPushButton("📊 Export Detailed Report")
        self.export_all_button.clicked.connect(self.export_detailed_report)
        self.export_all_button.setStyleSheet("padding: 10px;")
        button_layout.addWidget(self.export_all_button)
        
        proxy_layout.addLayout(button_layout)
        proxy_group.setLayout(proxy_layout)
        test_layout.addWidget(proxy_group)
        
        # Progress Bar
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        self.progress_label = QLabel("0%")
        progress_layout.addWidget(self.progress_label)
        test_layout.addLayout(progress_layout)
        
        # Results Table
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout()
        
        # Filter toolbar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Working Only", "Failed Only", "Elite Anonymity", "Fast (<1s)"])
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_combo)
        
        filter_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search proxies...")
        self.search_input.textChanged.connect(self.search_proxies)
        filter_layout.addWidget(self.search_input)
        
        filter_layout.addStretch()
        results_layout.addLayout(filter_layout)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(9)
        self.results_table.setHorizontalHeaderLabels([
            "Proxy", "Status", "Speed", "Response Time", "IP", "Location", 
            "Anonymity", "Protocol", "Error"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSortingEnabled(True)
        self.results_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_context_menu)
        results_layout.addWidget(self.results_table)
        
        results_group.setLayout(results_layout)
        test_layout.addWidget(results_group)
        
        # Statistics
        stats_layout = QHBoxLayout()
        self.stats_label = QLabel("Total: 0 | Working: 0 | Failed: 0 | Success Rate: 0%")
        self.stats_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        stats_layout.addWidget(self.stats_label)
        stats_layout.addStretch()
        
        self.speed_stats_label = QLabel("Avg Speed: N/A | Fastest: N/A | Slowest: N/A")
        stats_layout.addWidget(self.speed_stats_label)
        test_layout.addLayout(stats_layout)
        
        self.tabs.addTab(test_tab, "Proxy Testing")
        
        # Log Tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        log_layout.addWidget(QLabel("Activity Log:"))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(300)
        log_layout.addWidget(self.log_text)
        
        clear_log_button = QPushButton("Clear Log")
        clear_log_button.clicked.connect(lambda: self.log_text.clear())
        log_layout.addWidget(clear_log_button)
        log_layout.addStretch()
        
        self.tabs.addTab(log_tab, "Activity Log")
        
        # History Tab
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        history_layout.addWidget(QLabel("Test History:"))
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels([
            "Date/Time", "Total Tested", "Working", "Failed", "Success Rate"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        history_layout.addWidget(self.history_table)
        
        clear_history_button = QPushButton("Clear History")
        clear_history_button.clicked.connect(self.clear_history)
        history_layout.addWidget(clear_history_button)
        
        self.tabs.addTab(history_tab, "History")
        
        main_layout.addWidget(self.tabs)
        
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        import_action = QAction("Import Proxies", self)
        import_action.triggered.connect(self.import_proxies)
        file_menu.addAction(import_action)
        
        export_action = QAction("Export Working Proxies", self)
        export_action.triggered.connect(self.export_working_proxies)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        settings_action = QAction("Advanced Settings", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def show_settings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self)
        dialog.threads_spin.setValue(self.threads_spin.value())
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.threads_spin.setValue(dialog.threads_spin.value())
            self.auto_save = dialog.autosave_checkbox.isChecked()
            self.settings.setValue("max_workers", dialog.threads_spin.value())
            self.settings.setValue("auto_save", self.auto_save)
            self.log_message("Settings updated")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About Advanced Proxy Tester Pro",
                         "Advanced Proxy Tester Pro v2.0\n\n"
                         "A comprehensive proxy testing tool with:\n"
                         "• Multi-threaded concurrent testing\n"
                         "• Multiple protocol support (HTTP/HTTPS/SOCKS)\n"
                         "• Anonymity detection\n"
                         "• Detailed statistics and reporting\n"
                         "• Export functionality\n\n"
                         "Developed with PyQt6")
    
    def update_proxy_count(self):
        """Update proxy count label"""
        text = self.proxy_input.toPlainText().strip()
        if text:
            proxies = [p.strip() for p in text.split('\n') if p.strip()]
            self.proxy_count_label.setText(f"Proxies loaded: {len(proxies)}")
        else:
            self.proxy_count_label.setText("Proxies loaded: 0")
    
    def import_proxies(self):
        """Import proxies from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Proxies", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                self.proxy_input.setText(content)
                self.log_message(f"Imported proxies from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import file: {str(e)}")
    
    def paste_from_clipboard(self):
        """Paste from clipboard"""
        clipboard = QApplication.clipboard()
        self.proxy_input.setText(clipboard.text())
        self.log_message("Pasted proxies from clipboard")
    
    def clear_proxy_input(self):
        """Clear proxy input"""
        self.proxy_input.clear()
        self.log_message("Cleared proxy input")
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.status_bar.showMessage(message)
    
    def start_testing(self):
        """Start the proxy testing process"""
        proxy_text = self.proxy_input.toPlainText().strip()
        if not proxy_text:
            QMessageBox.warning(self, "Warning", "Please enter at least one proxy")
            return
        
        proxies = [p.strip() for p in proxy_text.split('\n') if p.strip()]
        
        if not proxies:
            QMessageBox.warning(self, "Warning", "No valid proxies found")
            return
        
        test_urls_text = self.url_input.toPlainText().strip()
        test_urls = [u.strip() for u in test_urls_text.split('\n') if u.strip()]
        
        if not test_urls:
            QMessageBox.warning(self, "Warning", "Please enter at least one test URL")
            return
        
        timeout = int(self.timeout_input.currentText())
        max_workers = self.threads_spin.value()
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.working_proxies.clear()
        self.failed_proxies.clear()
        self.progress_bar.setValue(0)
        
        # Disable/Enable buttons
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.proxy_input.setEnabled(False)
        
        self.log_message(f"Starting test of {len(proxies)} proxies with {max_workers} threads...")
        
        # Start testing thread
        self.tester_thread = ProxyTester(proxies, test_urls, timeout, max_workers)
        self.tester_thread.progress.connect(self.update_progress)
        self.tester_thread.result.connect(self.add_result)
        self.tester_thread.finished.connect(self.testing_finished)
        self.tester_thread.log_message.connect(self.log_message)
        self.tester_thread.start()
    
    def stop_testing(self):
        """Stop the testing process"""
        if self.tester_thread:
            self.tester_thread.stop()
            self.log_message("Stopping tests...")
    
    def update_progress(self, value):
        """Update the progress bar"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(f"{value}%")
    
    def add_result(self, result):
        """Add a test result to the table"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Proxy
        proxy_item = QTableWidgetItem(result['proxy'])
        self.results_table.setItem(row, 0, proxy_item)
        
        # Status
        status_item = QTableWidgetItem(result['status'])
        if result['status'] == 'Working':
            status_item.setForeground(QColor(0, 150, 0))
            status_item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            self.working_proxies.append(result)
        else:
            status_item.setForeground(QColor(200, 0, 0))
            self.failed_proxies.append(result)
        self.results_table.setItem(row, 1, status_item)
        
        # Speed Score
        speed_item = QTableWidgetItem(str(result['speed_score']))
        if result['speed_score'] >= 80:
            speed_item.setBackground(QColor(144, 238, 144))  # Light green
        elif result['speed_score'] >= 60:
            speed_item.setBackground(QColor(255, 255, 153))  # Light yellow
        elif result['speed_score'] > 0:
            speed_item.setBackground(QColor(255, 182, 193))  # Light red
        self.results_table.setItem(row, 2, speed_item)
        
        # Response Time
        self.results_table.setItem(row, 3, QTableWidgetItem(result['response_time']))
        
        # IP Address
        self.results_table.setItem(row, 4, QTableWidgetItem(result['ip']))
        
        # Location
        self.results_table.setItem(row, 5, QTableWidgetItem(result['location']))
        
        # Anonymity
        anonymity_item = QTableWidgetItem(result['anonymity'])
        if result['anonymity'] == 'Elite':
            anonymity_item.setForeground(QColor(0, 100, 200))
            anonymity_item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.results_table.setItem(row, 6, anonymity_item)
        
        # Protocol
        self.results_table.setItem(row, 7, QTableWidgetItem(result['protocol']))
        
        # Error
        self.results_table.setItem(row, 8, QTableWidgetItem(result['error']))
        
        # Update statistics
        self.update_statistics()
    
    def update_statistics(self):
        """Update statistics labels"""
        total = self.results_table.rowCount()
        working = len(self.working_proxies)
        failed = total - working
        success_rate = round(working / total * 100, 1) if total > 0 else 0
        
        self.stats_label.setText(
            f"Total: {total} | Working: {working} | Failed: {failed} | "
            f"Success Rate: {success_rate}%"
        )
        
        # Calculate speed statistics
        if self.working_proxies:
            response_times = []
            for proxy in self.working_proxies:
                rt = proxy['response_time']
                if rt != 'N/A':
                    try:
                        response_times.append(float(rt.replace('ms', '')))
                    except:
                        pass
            
            if response_times:
                avg_speed = round(sum(response_times) / len(response_times), 2)
                fastest = round(min(response_times), 2)
                slowest = round(max(response_times), 2)
                self.speed_stats_label.setText(
                    f"Avg Speed: {avg_speed}ms | Fastest: {fastest}ms | Slowest: {slowest}ms"
                )
    
    def testing_finished(self):
        """Handle testing completion"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.proxy_input.setEnabled(True)
        
        working = len(self.working_proxies)
        total = self.results_table.rowCount()
        success_rate = round(working / total * 100, 1) if total > 0 else 0
        
        self.log_message(
            f"Testing complete! {working}/{total} proxies working ({success_rate}% success)"
        )
        
        # Add to history
        self.add_to_history(total, working, total - working, success_rate)
        
        # Auto-save if enabled
        if self.auto_save and self.working_proxies:
            self.export_working_proxies()
        
        # Show completion message
        QMessageBox.information(
            self, "Testing Complete",
            f"Testing finished!\n\n"
            f"Total tested: {total}\n"
            f"Working: {working}\n"
            f"Failed: {total - working}\n"
            f"Success rate: {success_rate}%"
        )
    
    def add_to_history(self, total, working, failed, success_rate):
        """Add test to history"""
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.history_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.history_table.setItem(row, 1, QTableWidgetItem(str(total)))
        self.history_table.setItem(row, 2, QTableWidgetItem(str(working)))
        self.history_table.setItem(row, 3, QTableWidgetItem(str(failed)))
        self.history_table.setItem(row, 4, QTableWidgetItem(f"{success_rate}%"))
    
    def clear_history(self):
        """Clear test history"""
        self.history_table.setRowCount(0)
        self.log_message("Test history cleared")
    
    def clear_results(self):
        """Clear all results"""
        self.results_table.setRowCount(0)
        self.working_proxies.clear()
        self.failed_proxies.clear()
        self.progress_bar.setValue(0)
        self.progress_label.setText("0%")
        self.stats_label.setText("Total: 0 | Working: 0 | Failed: 0 | Success Rate: 0%")
        self.speed_stats_label.setText("Avg Speed: N/A | Fastest: N/A | Slowest: N/A")
        self.log_message("Results cleared")
    
    def export_working_proxies(self):
        """Export working proxies to a file"""
        if not self.working_proxies:
            QMessageBox.information(self, "Info", "No working proxies to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Working Proxies",
            f"working_proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    for proxy in self.working_proxies:
                        f.write(proxy['proxy'] + '\n')
                self.log_message(f"Exported {len(self.working_proxies)} working proxies to {file_path}")
                QMessageBox.information(self, "Success", f"Exported {len(self.working_proxies)} proxies successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")
    
    def export_detailed_report(self):
        """Export detailed report with all information"""
        if self.results_table.rowCount() == 0:
            QMessageBox.information(self, "Info", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Detailed Report",
            f"proxy_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    report = {
                        'timestamp': datetime.now().isoformat(),
                        'summary': {
                            'total': self.results_table.rowCount(),
                            'working': len(self.working_proxies),
                            'failed': len(self.failed_proxies),
                        },
                        'working_proxies': self.working_proxies,
                        'failed_proxies': self.failed_proxies
                    }
                    with open(file_path, 'w') as f:
                        json.dump(report, f, indent=2)
                else:  # CSV
                    with open(file_path, 'w') as f:
                        f.write("Proxy,Status,Speed Score,Response Time,IP,Location,Anonymity,Protocol,Error\n")
                        for proxy in self.working_proxies + self.failed_proxies:
                            f.write(f"{proxy['proxy']},{proxy['status']},{proxy['speed_score']},"
                                  f"{proxy['response_time']},{proxy['ip']},{proxy['location']},"
                                  f"{proxy['anonymity']},{proxy['protocol']},{proxy['error']}\n")
                
                self.log_message(f"Exported detailed report to {file_path}")
                QMessageBox.information(self, "Success", "Report exported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")
    
    def apply_filter(self, filter_type):
        """Apply filter to results table"""
        for row in range(self.results_table.rowCount()):
            show = True
            
            if filter_type == "Working Only":
                status = self.results_table.item(row, 1).text()
                show = status == "Working"
            elif filter_type == "Failed Only":
                status = self.results_table.item(row, 1).text()
                show = status != "Working"
            elif filter_type == "Elite Anonymity":
                anonymity = self.results_table.item(row, 6).text()
                show = anonymity == "Elite"
            elif filter_type == "Fast (<1s)":
                response_time = self.results_table.item(row, 3).text()
                if response_time != "N/A":
                    try:
                        time_ms = float(response_time.replace('ms', ''))
                        show = time_ms < 1000
                    except:
                        show = False
                else:
                    show = False
            
            self.results_table.setRowHidden(row, not show)
    
    def search_proxies(self, text):
        """Search proxies in results table"""
        for row in range(self.results_table.rowCount()):
            match = False
            for col in range(self.results_table.columnCount()):
                item = self.results_table.item(row, col)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.results_table.setRowHidden(row, not match)
    
    def show_context_menu(self, position):
        """Show context menu for results table"""
        menu = QMenu()
        
        copy_proxy = menu.addAction("Copy Proxy")
        copy_row = menu.addAction("Copy Row")
        menu.addSeparator()
        test_again = menu.addAction("Test Again")
        
        action = menu.exec(self.results_table.viewport().mapToGlobal(position))
        
        if action == copy_proxy:
            current_row = self.results_table.currentRow()
            if current_row >= 0:
                proxy = self.results_table.item(current_row, 0).text()
                QApplication.clipboard().setText(proxy)
                self.log_message(f"Copied proxy: {proxy}")
        elif action == copy_row:
            current_row = self.results_table.currentRow()
            if current_row >= 0:
                row_data = []
                for col in range(self.results_table.columnCount()):
                    item = self.results_table.item(current_row, col)
                    row_data.append(item.text() if item else "")
                QApplication.clipboard().setText("\t".join(row_data))
                self.log_message("Copied row data")
    
    def load_settings(self):
        """Load saved settings"""
        pass  # Settings already loaded in __init__
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.tester_thread and self.tester_thread.isRunning():
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "Testing is in progress. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.tester_thread.stop()
                self.tester_thread.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    window = ProxyTesterGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()