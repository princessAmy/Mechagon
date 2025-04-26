#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Name: Amy Janeway
Student ID: jke763
Class: IS-4543-001
Note: AI modeling language was used ONLY to make program follow UML standards
the program it's self was created from my own head

"""

import pyshark
import threading
import queue
import sqlite3
import pandas as pd
import platform
import subprocess

class PacketCapture:
    def __init__(self):
        self.interface = self.get_ethernet_port()
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        
    def get_ethernet_port(self):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()
        

        cursor.execute('SELECT Ethernet_Port FROM Constants LIMIT 1')
        ethernet_port = cursor.fetchone()
        
        print("Ethernet Port:", ethernet_port)
        conn.close()
        

        return ethernet_port[0] if ethernet_port else 'eth1'
    
    def capture_packets(self):
        capture = pyshark.LiveCapture(interface=self.interface)
        try:
            for packet in capture.sniff_continuously():
                if self.stop_event.is_set():
                    break  
                try:
                    packet_info = self.process_packet(packet)
                    if packet_info:
                        self.packet_queue.put(packet_info)
                except Exception:
                    print("Error processing packet")
        finally:
            capture.close()
    
    def process_packet(self, packet):
        packet_number = packet.number
        packet_length = packet.length
        source, destination = None, None
        
        if hasattr(packet, 'ip'):
            source = packet.ip.src
            destination = packet.ip.dst
        elif hasattr(packet, 'ipv6'):
            source = packet.ipv6.src
            destination = packet.ipv6.dst
        elif hasattr(packet, 'eth'):
            source = packet.eth.src
            destination = packet.eth.dst
        
        return (packet_number, packet_length, source, destination)
    
    def start_capture_thread(self):
        capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        capture_thread.start()
        return capture_thread

class DataBase:
    def get_data(self, table_name):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()

        query = 'SELECT * FROM "{}"'.format(table_name)
        cursor.execute(query)
        rows = cursor.fetchall()

        conn.close()
        return rows

    def insert_data_log(self, number, length, source, destination):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()
        
        query = 'INSERT INTO "data log" (Number, length, Source, Destination) VALUES (?, ?, ?, ?)'
        cursor.execute(query, (number, length, source, destination))
        
        conn.commit()
        conn.close()

    def insert_whitelist(self, source):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()
        
        query = 'INSERT OR IGNORE INTO "WhiteList" (Source) VALUES (?)'
        cursor.execute(query, (source,))
        
        conn.commit()
        conn.close()

    def insert_blacklist(self, source):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()
        
        query = 'INSERT OR IGNORE INTO "BlackList" (Source) VALUES (?)'
        cursor.execute(query, (source,))
        
        conn.commit()
        conn.close()
        
    def remove_whitelist(self, source):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()

        query = 'DELETE FROM WhiteList WHERE Source = ?'
        cursor.execute(query, (source,))
        
        conn.commit()
        conn.close()

    def remove_blacklist(self, source):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()

        query = 'DELETE FROM BlackList WHERE Source = ?'
        cursor.execute(query, (source,))
        
        conn.commit()
        conn.close()
        
    def update_constants(self, ethernet_port, size_limit):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()

        cursor.execute('DELETE FROM Constants WHERE rowid NOT IN (SELECT MIN(rowid) FROM Constants)')

        cursor.execute('SELECT COUNT(*) FROM Constants')
        count = cursor.fetchone()[0]
        
        if count == 0:
            cursor.execute('INSERT INTO Constants ("Ethernet_Port", "Size_Limit") VALUES (?, ?)', (ethernet_port, size_limit))
        else:
            cursor.execute('UPDATE Constants SET "Ethernet_Port" = ?, "Size_Limit" = ?', (ethernet_port, size_limit))
        
        conn.commit()
        conn.close()
        
        
    def create_database(self):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()

        # Create table for data log
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS "data log" (
            id STRING PRIMARY KEY,
            Number STRING,
            length STRING,
            Source STRING,
            Destination STRING
        )
        ''')

        # Create table for WhiteList
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS WhiteList (
            Source STRING UNIQUE
        )
        ''')

        # Create table for BlackList
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS BlackList (
            Source STRING UNIQUE
        )
        ''')

        # Create table for Constants
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Constants (
            Ethernet_Port STRING,
            Size_Limit STRING
        )
        ''')
        cursor.execute("SELECT COUNT(*) FROM Constants")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO Constants (Ethernet_Port, Size_Limit) VALUES (?, ?)", ("eth1", 90))

        conn.commit()
        conn.close()


    #purge the scanner data and transfer it to a excel sheet (Only use if needed)
    def Resistance_Is_futile(self, FileName):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()
        
        # Export data from the data log table to a Pandas DataFrame
        df = pd.read_sql_query('SELECT * FROM "data log"', conn)
        
        # Save the DataFrame to an Excel file
        df.to_excel(f"{FileName}", index=False)

        # Purge the data from the data log table
        cursor.execute('DELETE FROM "data log"')
        conn.commit()

        conn.close()
        return True
    
class FireWall:
    def block_ip(self, ip):
        os_type = platform.system()
        
        if ':' in ip:  # IPv6 case
            incoming = f"sudo ip6tables -A INPUT -s {ip} -j DROP"
            outgoing = f"sudo ip6tables -A OUTPUT -d {ip} -j DROP"
        else:  # IPv4 case
            incoming = f"sudo iptables -A INPUT -s {ip} -j DROP"
            outgoing = f"sudo iptables -A OUTPUT -d {ip} -j DROP"
        
        if os_type == "Linux":
            try:
                subprocess.run(incoming, shell=True, check=True)
                subprocess.run(outgoing, shell=True, check=True)
                return f"Blocking {ip}"
            except subprocess.CalledProcessError:
                return f"Failed to block {ip}"
        else:
            return "OS is not supported"
    
    def unblock_ip(self, ip):
        os_type = platform.system()
        
        if ':' in ip:  # IPv6 case
            incoming = f"sudo ip6tables -D INPUT -s {ip} -j DROP"
            outgoing = f"sudo ip6tables -D OUTPUT -d {ip} -j DROP"
        else:  # IPv4 case
            incoming = f"sudo iptables -D INPUT -s {ip} -j DROP"
            outgoing = f"sudo iptables -D OUTPUT -d {ip} -j DROP"
        
        if os_type == "Linux":
            try:
                subprocess.run(incoming, shell=True, check=True)
                subprocess.run(outgoing, shell=True, check=True)
                return f"Unblocking {ip}"
            except subprocess.CalledProcessError:
                return f"Failed to unblock {ip}"
        else:
            return "OS is not supported"
    
    def get_size_limit(self):
        conn = sqlite3.connect("mechagondata.db")
        cursor = conn.cursor()
        
        cursor.execute('SELECT Size_Limit FROM Constants LIMIT 1')
        size_limit = cursor.fetchone()
        
        conn.close()
        return size_limit
        



if __name__ == "__main__":
    db = DataBase()
    db.create_database()
    
    
    packet_capture = PacketCapture()
    fw = FireWall()
    
    thread = packet_capture.start_capture_thread()
    log_data = db.get_data("data log")
    
    
    startupblacklist = db.get_data("Blacklist")
    startupwhitelist = db.get_data("Whitelist")

    blacklist_ips = [item[0] for item in startupblacklist]
    whitelist_ips = [item[0] for item in startupwhitelist]

    for ip in blacklist_ips:
        print(fw.block_ip(ip))

    for ip in whitelist_ips:
        print(fw.unblock_ip(ip))
        
    
    subprocess.Popen(["python", "Mechagon UI.py"])
    
    
    try:
        while True:
            try:
                packet_info = packet_capture.packet_queue.get(timeout=1)
                db.insert_data_log(*packet_info)
                limit = fw.get_size_limit()[0]
                whitelist = [item[0] for item in db.get_data("Whitelist")]
                blacklist = [item[0] for item in db.get_data("Blacklist")]
                sender =packet_info[2]
                packetsize = int(packet_info[1])
                if sender not in whitelist:
                    if packetsize >= limit-1:
                        fw.block_ip(sender)
                        db.insert_blacklist(sender)
            except queue.Empty:
                pass

            
       
    except KeyboardInterrupt:
        packet_capture.stop_event.set()  
        thread.join()
        print("Packet capture stopped.")