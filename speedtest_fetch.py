#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import base64
from urllib.parse import quote, unquote, urlparse, ParseResult
import socket
import time
import concurrent.futures
from typing import List, Union

class Node:
    def __init__(self, data: Union[dict, str]) -> None:
        if isinstance(data, dict):
            self.data = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else:
            raise TypeError(f"Got {type(data)}")
        self.data['type'] = self.type
        self.fix()
        self.names = {self.data.get('name', '未命名')}
        self.latency = float('inf')

    def fix(self):
        if not self.data.get('name'):
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        assert 'server' in self.data
        self.data['port'] = int(self.data['port'])

    @classmethod
    def urlparse(cls, url: str, scheme='', allow_fragments=True):
        if allow_fragments and '#' in url:
            segs = url.split('#')
            fragment = segs[-1]
            url = '#'.join(segs[:-1])
        else:
            fragment = None
        try:
            res = urlparse(url, scheme, allow_fragments=False)
        except ValueError:
            res = cls.urlparse0(url, scheme)
        if fragment:
            res = res._replace(fragment=fragment)
        return res

    @classmethod
    def urlparse0(cls, url: str, scheme=''):
        if '#' in url:
            segs = url.split('#')
            fragment = segs[-1]
            url = '#'.join(segs[:-1])
        else:
            fragment = ''
        scheme0, r = url.split('://', 1)
        netloc, query = r.split('?', 1)
        netloc = netloc.rstrip('/')
        return ParseResult(scheme0 or scheme, netloc, '', '', query, fragment)

    def load_url(self, url: str):
        try:
            self.type, dt = url.split("://", 1)
        except ValueError:
            raise Exception(f"Not a node: {url}")
        if self.type == 'hy2':
            self.type = 'hysteria2'
        
        loader = getattr(self, '_load_' + self.type, None)
        if loader:
            loader(url, dt)
        else:
            # 兼容通用链接解析
            parsed = self.urlparse(url)
            self.data = {
                'name': unquote(parsed.fragment or '未命名'),
                'server': parsed.hostname or '0.0.0.0',
                'port': parsed.port or 443,
                'type': self.type
            }

    def _load_ss(self, url: str, dt: str):
        info = dt.split('@')
        srvname = info.pop()
        srv, name = srvname.split('#') if '#' in srvname else (srvname, '')
        segs = srv.split(':')
        self.data = {'name': unquote(name), 'server': ':'.join(segs[:-1]), 'port': int(segs[-1]), 'type': 'ss'}

    def _load_trojan(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment or 'trojan'), 'server': parsed.hostname, 'port': parsed.port or 443, 'type': 'trojan'}

    def _load_vless(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment or 'vless'), 'server': parsed.hostname, 'port': parsed.port or 443, 'type': 'vless'}

    def _load_hysteria2(self, url: str, dt: str):
        parsed = self.urlparse(url)
        ports = parsed.netloc.split(':')[1] if ':' in parsed.netloc else '443'
        port = int(ports.split(',')[0]) if ',' in ports else int(ports)
        self.data = {'name': unquote(parsed.fragment or 'hysteria2'), 'server': parsed.hostname, 'port': port, 'type': 'hysteria2'}

    def _load_anytls(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment or 'anytls'), 'server': parsed.hostname, 'port': parsed.port or 443, 'type': 'anytls'}

    def _load_tuic(self, url: str, dt: str):
        parsed = self.urlparse(url)
        self.data = {'name': unquote(parsed.fragment or 'tuic'), 'server': parsed.hostname, 'port': parsed.port or 136, 'type': 'tuic'}

    @property
    def name(self):
        return sorted(list(self.names))[0]

def test_node_latency(node: Node, timeout: float = 2.5) -> float:
    """通过 TCPing 测试节点的服务器响应延迟（毫秒）"""
    server = node.data['server'].strip('[]')
    port = node.data['port']
    start_time = time.time()
    try:
        with socket.create_connection((server, port), timeout=timeout):
            return round((time.time() - start_time) * 1000, 2)
    except Exception:
        return float('inf')

def main():
    print("=== 节点多线程测速与 Top 50 优选工具 ===")
    
    # 模拟读取本地订阅文件或列表
    raw_node_urls = []
    try:
        with open("list.txt", "r", encoding="utf-8") as f:
            raw_node_urls = [line.strip() for line in f if line.strip() and "://" in line]
    except FileNotFoundError:
        print("未检测到本地 list.txt，将自动尝试从 fetch.py 或内置源收集测试...")
        # 兼容演示用的模拟节点
        for i in range(1, 60):
            raw_node_urls.append(f"vless://uuid-test@{i}.example.com:443#测试节点-{i}")

    print(f"成功加载共计 {len(raw_node_urls)} 个节点，正在开始并发 TCPing 测速...")

    nodes: List[Node] = []
    for u in raw_node_urls:
        try:
            nodes.append(Node(u))
        except Exception:
            continue

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_to_node = {executor.submit(test_node_latency, node): node for node in nodes}
        for future in concurrent.futures.as_completed(future_to_node):
            node = future_to_node[future]
            try:
                latency = future.result()
                node.latency = latency
                if latency != float('inf'):
                    results.append(node)
            except Exception:
                pass

    # 按延迟从小到大排序
    results.sort(key=lambda x: x.latency)

    # 优选出前 50 个节点
    top_50 = results[:50]

    print(f"\n测速完成！有效存活节点总数: {len(results)} 个。已为您精选出延迟最低的前 {len(top_50)} 个优质节点：")
    for i, node in enumerate(top_50, 1):
        print(f"No.{i:02d} | 延迟: {node.latency:6.2f} ms | 类型: {node.type.upper():<10} | 名称: {node.name}")

    # 导出优选结果到文件
    output_filename = "top50_optimized_nodes.txt"
    with open(output_filename, "w", encoding="utf-8") as f:
        for node in top_50:
            f.write(f"{node.data.get('url', '#')}\n")
    print(f"\n前 50 个优选节点已成功保存至: {output_filename}")

if __name__ == '__main__':
    main()
