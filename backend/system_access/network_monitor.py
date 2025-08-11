"""
Moniteur réseau temps réel avec détection d'anomalies
Capture et analyse du trafic réseau
"""

import os
import asyncio
import logging
import socket
import struct
import json
from typing import Dict, List, Set, Optional, Callable, Tuple
from datetime import datetime
from collections import defaultdict, deque
import ipaddress
import hashlib

from .os_detector import system_access, OSType

logger = logging.getLogger(__name__)

class NetworkMonitor:
    """Surveillance réseau avancée avec détection de patterns malveillants"""
    
    def __init__(self):
        self.os_type = system_access.os_type
        self.is_monitoring = False
        self.network_callbacks: List[Callable] = []
        self.packet_buffer = deque(maxlen=10000)
        self.connection_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'first_seen': None, 'last_seen': None})
        self.dns_cache = {}
        self.suspicious_ips = set()
        self.suspicious_domains = set()
        self.c2_indicators = []
        self.dga_scores = {}
        
        # Ports suspects connus
        self.suspicious_ports = {
            20, 21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 4444, 5900,
            5985, 5986, 8080, 8443, 8888, 9999, 1337, 31337, 12345, 54321
        }
        
        # Patterns C2 connus
        self.c2_patterns = {
            'cobalt_strike': {
                'ja3': ['a0e9f5d64349fb13191bc781f81f42e1', '72a589da586844d7f0818ce684948eea'],
                'user_agents': ['Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'],
                'uri_patterns': ['/api/v1/updates', '/api/v2/downloads', '/submit.php'],
                'ports': [80, 443, 8080, 8443]
            },
            'metasploit': {
                'ja3': ['b0be3ae2813f0e28b3c01991f930c3ea'],
                'user_agents': ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)'],
                'ports': [4444, 4445, 8080, 8443]
            },
            'empire': {
                'user_agents': ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'],
                'uri_patterns': ['/login/process.php', '/admin/get.php', '/news.php'],
                'ports': [80, 443, 8080, 8443]
            }
        }
        
        self._setup_capture()
    
    def _setup_capture(self):
        """Configurer la capture réseau selon l'OS"""
        self.capture_available = False
        
        if self.os_type == OSType.WINDOWS:
            try:
                import winpcapy
                self.capture_method = 'winpcap'
                self.capture_available = True
            except ImportError:
                try:
                    import scapy.all as scapy
                    self.scapy = scapy
                    self.capture_method = 'scapy'
                    self.capture_available = True
                except ImportError:
                    logger.warning("Aucune bibliothèque de capture disponible (WinPcap/Scapy)")
                    
        elif self.os_type == OSType.LINUX:
            try:
                import pcapy
                self.pcapy = pcapy
                self.capture_method = 'pcapy'
                self.capture_available = True
            except ImportError:
                try:
                    import scapy.all as scapy
                    self.scapy = scapy
                    self.capture_method = 'scapy'
                    self.capture_available = True
                except ImportError:
                    logger.warning("Aucune bibliothèque de capture disponible (pcapy/Scapy)")
                    
        # Fallback sur socket si admin
        if not self.capture_available and system_access.is_admin:
            self.capture_method = 'raw_socket'
            self.capture_available = True
    
    async def start_monitoring(self, interface: Optional[str] = None):
        """Démarrer la surveillance réseau"""
        if self.is_monitoring:
            return
            
        if not self.capture_available:
            logger.error("Capture réseau non disponible - privilèges admin requis")
            return
            
        self.is_monitoring = True
        logger.info(f"🔍 Démarrage de la surveillance réseau (méthode: {self.capture_method})")
        
        # Lancer la capture selon la méthode
        if self.capture_method == 'scapy':
            asyncio.create_task(self._scapy_capture(interface))
        elif self.capture_method == 'pcapy':
            asyncio.create_task(self._pcapy_capture(interface))
        elif self.capture_method == 'raw_socket':
            asyncio.create_task(self._raw_socket_capture())
        
        # Lancer l'analyse
        asyncio.create_task(self._analyze_traffic())
        
        # Surveillance DNS
        asyncio.create_task(self._monitor_dns())
    
    async def _scapy_capture(self, interface: Optional[str] = None):
        """Capture avec Scapy"""
        def packet_handler(packet):
            asyncio.create_task(self._process_packet(packet))
        
        try:
            # Capturer en mode asynchrone
            self.scapy.sniff(
                iface=interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_monitoring
            )
        except Exception as e:
            logger.error(f"Erreur capture Scapy: {e}")
    
    async def _raw_socket_capture(self):
        """Capture avec socket raw (Windows/Linux admin)"""
        try:
            if self.os_type == OSType.WINDOWS:
                # Socket raw Windows
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Socket raw Linux
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            while self.is_monitoring:
                try:
                    data, addr = sock.recvfrom(65535)
                    await self._process_raw_packet(data)
                except Exception as e:
                    logger.error(f"Erreur capture socket: {e}")
                    await asyncio.sleep(0.1)
                    
            if self.os_type == OSType.WINDOWS:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            
        except Exception as e:
            logger.error(f"Erreur socket raw: {e}")
    
    async def _process_packet(self, packet):
        """Traiter un paquet capturé"""
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'layers': []
            }
            
            # Analyser les couches
            if hasattr(packet, 'haslayer'):
                # IP Layer
                if packet.haslayer('IP'):
                    ip_layer = packet['IP']
                    packet_info['src_ip'] = ip_layer.src
                    packet_info['dst_ip'] = ip_layer.dst
                    packet_info['protocol'] = ip_layer.proto
                    packet_info['layers'].append('IP')
                
                # TCP Layer
                if packet.haslayer('TCP'):
                    tcp_layer = packet['TCP']
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                    packet_info['tcp_flags'] = tcp_layer.flags
                    packet_info['layers'].append('TCP')
                    
                    # Calculer JA3 pour TLS
                    if tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        ja3_hash = self._calculate_ja3(packet)
                        if ja3_hash:
                            packet_info['ja3'] = ja3_hash
                
                # UDP Layer
                elif packet.haslayer('UDP'):
                    udp_layer = packet['UDP']
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport
                    packet_info['layers'].append('UDP')
                
                # DNS Layer
                if packet.haslayer('DNS'):
                    dns_layer = packet['DNS']
                    packet_info['layers'].append('DNS')
                    packet_info['dns_query'] = self._extract_dns_query(dns_layer)
                
                # HTTP Layer
                if packet.haslayer('Raw'):
                    raw_data = packet['Raw'].load
                    if b'HTTP' in raw_data[:100]:
                        packet_info['layers'].append('HTTP')
                        packet_info['http_data'] = self._extract_http_info(raw_data)
            
            # Ajouter au buffer
            self.packet_buffer.append(packet_info)
            
            # Mettre à jour les statistiques
            if 'src_ip' in packet_info and 'dst_ip' in packet_info:
                conn_key = f"{packet_info['src_ip']}:{packet_info.get('src_port', 0)}->{packet_info['dst_ip']}:{packet_info.get('dst_port', 0)}"
                self.connection_stats[conn_key]['packets'] += 1
                self.connection_stats[conn_key]['bytes'] += packet_info['size']
                if not self.connection_stats[conn_key]['first_seen']:
                    self.connection_stats[conn_key]['first_seen'] = packet_info['timestamp']
                self.connection_stats[conn_key]['last_seen'] = packet_info['timestamp']
            
            # Détecter les anomalies
            await self._detect_network_anomalies(packet_info)
            
        except Exception as e:
            logger.debug(f"Erreur traitement paquet: {e}")
    
    async def _process_raw_packet(self, data: bytes):
        """Traiter un paquet raw"""
        try:
            # Parser l'en-tête IP
            ip_header = data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(data),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'layers': ['IP']
            }
            
            # TCP
            if protocol == 6:
                tcp_header = data[iph_length:iph_length+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                packet_info['src_port'] = tcph[0]
                packet_info['dst_port'] = tcph[1]
                packet_info['layers'].append('TCP')
            
            # UDP
            elif protocol == 17:
                udp_header = data[iph_length:iph_length+8]
                udph = struct.unpack('!HHHH', udp_header)
                packet_info['src_port'] = udph[0]
                packet_info['dst_port'] = udph[1]
                packet_info['layers'].append('UDP')
            
            self.packet_buffer.append(packet_info)
            await self._detect_network_anomalies(packet_info)
            
        except Exception as e:
            logger.debug(f"Erreur parsing paquet raw: {e}")
    
    async def _analyze_traffic(self):
        """Analyser le trafic en continu"""
        while self.is_monitoring:
            try:
                # Analyser les patterns de communication
                await self._analyze_communication_patterns()
                
                # Détecter le beaconing C2
                await self._detect_c2_beaconing()
                
                # Analyser le volume de trafic
                await self._analyze_traffic_volume()
                
                # Détecter le scan de ports
                await self._detect_port_scanning()
                
                await asyncio.sleep(5)  # Analyse toutes les 5 secondes
                
            except Exception as e:
                logger.error(f"Erreur analyse trafic: {e}")
                await asyncio.sleep(10)
    
    async def _detect_network_anomalies(self, packet: Dict):
        """Détecter les anomalies réseau"""
        anomalies = []
        
        # Port suspect
        dst_port = packet.get('dst_port', 0)
        if dst_port in self.suspicious_ports:
            anomalies.append({
                'type': 'suspicious_port',
                'severity': 'medium',
                'details': f"Communication vers port suspect: {dst_port}"
            })
        
        # IP suspecte
        dst_ip = packet.get('dst_ip', '')
        if dst_ip in self.suspicious_ips:
            anomalies.append({
                'type': 'suspicious_ip',
                'severity': 'high',
                'details': f"Communication vers IP suspecte: {dst_ip}"
            })
        
        # JA3 C2 connu
        ja3 = packet.get('ja3', '')
        for c2_type, indicators in self.c2_patterns.items():
            if ja3 in indicators.get('ja3', []):
                anomalies.append({
                    'type': 'c2_communication',
                    'severity': 'critical',
                    'details': f"Signature JA3 {c2_type} détectée: {ja3}"
                })
        
        # DNS suspect
        dns_query = packet.get('dns_query', '')
        if dns_query:
            dga_score = self._calculate_dga_score(dns_query)
            if dga_score > 0.7:
                anomalies.append({
                    'type': 'dga_domain',
                    'severity': 'high',
                    'details': f"Domaine DGA potentiel: {dns_query} (score: {dga_score:.2f})"
                })
        
        # HTTP suspect
        http_data = packet.get('http_data', {})
        if http_data:
            user_agent = http_data.get('user_agent', '')
            for c2_type, indicators in self.c2_patterns.items():
                if user_agent in indicators.get('user_agents', []):
                    anomalies.append({
                        'type': 'c2_communication',
                        'severity': 'critical',
                        'details': f"User-Agent {c2_type} détecté"
                    })
        
        # Notifier si anomalies
        if anomalies:
            await self._notify_callbacks({
                'event': 'network_anomaly_detected',
                'packet': packet,
                'anomalies': anomalies,
                'timestamp': datetime.now().isoformat()
            })
    
    def _calculate_ja3(self, packet) -> Optional[str]:
        """Calculer l'empreinte JA3 d'une connexion TLS"""
        try:
            if not hasattr(packet, 'haslayer') or not packet.haslayer('TLS'):
                return None
            
            # Extraire les paramètres TLS
            tls_layer = packet['TLS']
            
            # TODO: Implémenter le calcul JA3 complet
            # Pour l'instant, retourner un hash simple
            tls_data = str(tls_layer).encode()
            return hashlib.md5(tls_data).hexdigest()
            
        except Exception:
            return None
    
    def _extract_dns_query(self, dns_layer) -> str:
        """Extraire la requête DNS"""
        try:
            if hasattr(dns_layer, 'qd') and dns_layer.qd:
                return dns_layer.qd.qname.decode('utf-8').rstrip('.')
        except:
            pass
        return ''
    
    def _extract_http_info(self, raw_data: bytes) -> Dict:
        """Extraire les informations HTTP"""
        try:
            data_str = raw_data.decode('utf-8', errors='ignore')
            lines = data_str.split('\r\n')
            
            http_info = {}
            
            # Première ligne (méthode, URI, version)
            if lines and ' ' in lines[0]:
                parts = lines[0].split(' ')
                if len(parts) >= 3:
                    http_info['method'] = parts[0]
                    http_info['uri'] = parts[1]
                    http_info['version'] = parts[2]
            
            # Headers
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    if key.lower() == 'user-agent':
                        http_info['user_agent'] = value
                    elif key.lower() == 'host':
                        http_info['host'] = value
            
            return http_info
            
        except Exception:
            return {}
    
    def _calculate_dga_score(self, domain: str) -> float:
        """Calculer le score DGA d'un domaine"""
        if not domain or '.' not in domain:
            return 0.0
        
        # Extraire le nom de domaine principal
        parts = domain.split('.')
        if len(parts) < 2:
            return 0.0
        
        main_domain = parts[-2]  # Partie avant le TLD
        
        # Caractéristiques DGA
        score = 0.0
        
        # Longueur
        if len(main_domain) > 15:
            score += 0.2
        if len(main_domain) > 20:
            score += 0.2
        
        # Ratio consonnes/voyelles
        vowels = sum(1 for c in main_domain.lower() if c in 'aeiou')
        consonants = len(main_domain) - vowels
        if vowels > 0:
            ratio = consonants / vowels
            if ratio > 3:
                score += 0.3
        else:
            score += 0.4  # Pas de voyelles
        
        # Entropie
        entropy = self._calculate_entropy(main_domain)
        if entropy > 3.5:
            score += 0.2
        if entropy > 4.0:
            score += 0.2
        
        # Chiffres
        digit_count = sum(1 for c in main_domain if c.isdigit())
        if digit_count > len(main_domain) * 0.3:
            score += 0.3
        
        # N-grammes suspects
        suspicious_ngrams = ['xz', 'qx', 'qz', 'jx', 'jz', 'vx', 'vz', 'wx', 'wz']
        if any(ng in main_domain.lower() for ng in suspicious_ngrams):
            score += 0.2
        
        return min(score, 1.0)
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculer l'entropie de Shannon"""
        import math
        
        if not s:
            return 0.0
        
        # Compter les occurrences
        counts = {}
        for c in s:
            counts[c] = counts.get(c, 0) + 1
        
        # Calculer l'entropie
        entropy = 0.0
        length = len(s)
        
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    async def _monitor_dns(self):
        """Surveiller les requêtes DNS"""
        while self.is_monitoring:
            try:
                # Analyser les requêtes DNS récentes
                dns_packets = [
                    p for p in self.packet_buffer 
                    if 'dns_query' in p and p['dns_query']
                ]
                
                # Détecter les rafales DNS (DNS tunneling)
                dns_burst_threshold = 20
                if len(dns_packets) > dns_burst_threshold:
                    # Vérifier le timing
                    recent_dns = [
                        p for p in dns_packets
                        if (datetime.now() - datetime.fromisoformat(p['timestamp'])).seconds < 10
                    ]
                    
                    if len(recent_dns) > dns_burst_threshold:
                        await self._notify_callbacks({
                            'event': 'dns_tunneling_suspected',
                            'count': len(recent_dns),
                            'timestamp': datetime.now().isoformat(),
                            'severity': 'high'
                        })
                
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Erreur surveillance DNS: {e}")
                await asyncio.sleep(30)
    
    async def _analyze_communication_patterns(self):
        """Analyser les patterns de communication"""
        # Grouper par destination
        destination_stats = defaultdict(lambda: {'count': 0, 'bytes': 0, 'ports': set()})
        
        for conn_key, stats in self.connection_stats.items():
            if '->' in conn_key:
                dst_part = conn_key.split('->')[1]
                dst_ip = dst_part.split(':')[0]
                dst_port = int(dst_part.split(':')[1])
                
                destination_stats[dst_ip]['count'] += stats['packets']
                destination_stats[dst_ip]['bytes'] += stats['bytes']
                destination_stats[dst_ip]['ports'].add(dst_port)
        
        # Détecter les anomalies
        for dst_ip, stats in destination_stats.items():
            # Beaucoup de ports différents (scan)
            if len(stats['ports']) > 50:
                await self._notify_callbacks({
                    'event': 'port_scan_detected',
                    'target_ip': dst_ip,
                    'port_count': len(stats['ports']),
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'high'
                })
    
    async def _detect_c2_beaconing(self):
        """Détecter le beaconing C2"""
        # Analyser les intervalles de communication
        for conn_key, stats in self.connection_stats.items():
            if stats['packets'] < 10:
                continue
            
            # Calculer l'intervalle moyen
            if stats['first_seen'] and stats['last_seen']:
                first = datetime.fromisoformat(stats['first_seen'])
                last = datetime.fromisoformat(stats['last_seen'])
                duration = (last - first).seconds
                
                if duration > 0:
                    avg_interval = duration / stats['packets']
                    
                    # Intervalles réguliers suspects (30s à 5min)
                    if 30 <= avg_interval <= 300:
                        await self._notify_callbacks({
                            'event': 'c2_beaconing_detected',
                            'connection': conn_key,
                            'interval': avg_interval,
                            'timestamp': datetime.now().isoformat(),
                            'severity': 'critical'
                        })
    
    async def _analyze_traffic_volume(self):
        """Analyser le volume de trafic"""
        # Détecter l'exfiltration de données
        for conn_key, stats in self.connection_stats.items():
            # Plus de 100MB vers l'extérieur
            if stats['bytes'] > 100 * 1024 * 1024:
                if '->' in conn_key:
                    dst_ip = conn_key.split('->')[1].split(':')[0]
                    
                    # Vérifier si c'est une IP externe
                    try:
                        ip_obj = ipaddress.ip_address(dst_ip)
                        if not ip_obj.is_private:
                            await self._notify_callbacks({
                                'event': 'data_exfiltration_suspected',
                                'connection': conn_key,
                                'volume_mb': stats['bytes'] / (1024 * 1024),
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'critical'
                            })
                    except:
                        pass
    
    async def _detect_port_scanning(self):
        """Détecter les scans de ports"""
        # Analyser les tentatives de connexion échouées
        src_port_attempts = defaultdict(set)
        
        for packet in list(self.packet_buffer)[-1000:]:  # Derniers 1000 paquets
            if 'tcp_flags' in packet:
                # SYN sans ACK = tentative
                if packet['tcp_flags'] == 0x02:  # SYN only
                    src_ip = packet.get('src_ip', '')
                    dst_port = packet.get('dst_port', 0)
                    if src_ip and dst_port:
                        src_port_attempts[src_ip].add(dst_port)
        
        # Détecter les scans
        for src_ip, ports in src_port_attempts.items():
            if len(ports) > 20:
                await self._notify_callbacks({
                    'event': 'port_scan_detected',
                    'source_ip': src_ip,
                    'scanned_ports': len(ports),
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'high'
                })
    
    async def _notify_callbacks(self, event: Dict):
        """Notifier les callbacks"""
        for callback in self.network_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Erreur callback réseau: {e}")
    
    def add_callback(self, callback: Callable):
        """Ajouter un callback pour les événements réseau"""
        self.network_callbacks.append(callback)
    
    def add_suspicious_ip(self, ip: str):
        """Ajouter une IP suspecte"""
        self.suspicious_ips.add(ip)
    
    def add_suspicious_domain(self, domain: str):
        """Ajouter un domaine suspect"""
        self.suspicious_domains.add(domain)
    
    def get_network_stats(self) -> Dict:
        """Obtenir les statistiques réseau"""
        return {
            'total_packets': len(self.packet_buffer),
            'active_connections': len(self.connection_stats),
            'suspicious_ips': list(self.suspicious_ips),
            'suspicious_domains': list(self.suspicious_domains),
            'top_talkers': self._get_top_talkers(),
            'protocol_distribution': self._get_protocol_distribution()
        }
    
    def _get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Obtenir les IPs qui communiquent le plus"""
        ip_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        for conn_key, stats in self.connection_stats.items():
            if '->' in conn_key:
                src_ip = conn_key.split('->')[0].split(':')[0]
                ip_stats[src_ip]['packets'] += stats['packets']
                ip_stats[src_ip]['bytes'] += stats['bytes']
        
        # Trier par bytes
        sorted_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )[:limit]
        
        return [
            {'ip': ip, 'packets': stats['packets'], 'bytes': stats['bytes']}
            for ip, stats in sorted_ips
        ]
    
    def _get_protocol_distribution(self) -> Dict[str, int]:
        """Obtenir la distribution des protocoles"""
        protocols = defaultdict(int)
        
        for packet in self.packet_buffer:
            for layer in packet.get('layers', []):
                protocols[layer] += 1
        
        return dict(protocols)
    
    async def block_ip(self, ip: str) -> bool:
        """Bloquer une IP (nécessite privilèges admin)"""
        if not system_access.is_admin:
            logger.error("Privilèges admin requis pour bloquer une IP")
            return False
        
        try:
            if self.os_type == OSType.WINDOWS:
                # Windows Firewall
                import subprocess
                cmd = f'netsh advfirewall firewall add rule name="RansomGuard_Block_{ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True)
                
            elif self.os_type == OSType.LINUX:
                # iptables
                import subprocess
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                
            logger.info(f"IP {ip} bloquée")
            return True
            
        except Exception as e:
            logger.error(f"Erreur blocage IP {ip}: {e}")
            return False
    
    async def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.is_monitoring = False
        logger.info("🛑 Surveillance réseau arrêtée")
