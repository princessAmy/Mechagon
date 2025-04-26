#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Name: Amy Janeway
Student ID: jke763
Class: IS-4543-001
Note: AI modeling language was used ONLY to make program follow UML standards
the program it's self was created from my own head

The starting base for the ui is from: https://pyuibuilder.com
"""


import tkinter as tk
from tkinter import ttk
import sqlite3
from mechagon import DataBase, FireWall


class User_Interface:
    def __init__(self):
        self.conn = sqlite3.connect("mechagondata.db")
        self.cursor = self.conn.cursor()

        self.ethernet_port = self.get_current_ethernet_port()
        self.size_limit = self.get_packet_size_limit()

    def get_current_ethernet_port(self):
        self.cursor.execute("SELECT Ethernet_Port FROM Constants LIMIT 1")
        result = self.cursor.fetchone()
        if result:
            return result[0]

    def get_packet_size_limit(self):
        self.cursor.execute("SELECT Size_Limit FROM Constants LIMIT 1")
        result = self.cursor.fetchone()
        if result:
            return result[0]

    def create_ui(self):
        self.mechagon = tk.Tk()
        self.mechagon.config(bg="#292929")
        self.mechagon.title("Mechagon")
        self.mechagon.geometry("1200x719")

        frame = tk.Frame(master=self.mechagon, bg="#292929")
        frame.pack(side=tk.BOTTOM)

        frame1 = tk.Frame(master=frame, bg="#393636")
        frame1.grid(row=0, column=0)

        blacklist_label = tk.Label(master=frame1, text="Black list", bg="#393636", fg="#ffffff", font=("TkDefaultFont", 33), width=10)
        blacklist_label.pack(side=tk.TOP)

        self.blacklist_tree = self.create_table_widget(frame1, "BlackList")

        frame2 = tk.Frame(master=frame, bg="#393636")
        frame2.grid(row=0, column=1)

        whitelist_label = tk.Label(master=frame2, text="White list", bg="#393636", fg="#ffffff", font=("TkDefaultFont", 33), width=10)
        whitelist_label.pack(side=tk.TOP)

        self.whitelist_tree = self.create_table_widget(frame2, "WhiteList")

        terminal_frame = tk.Frame(self.mechagon)
        terminal_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Terminal data
        self.terminal_tree = ttk.Treeview(terminal_frame, columns=("Packet Number", "Packet Size", "Source", "Destination"), show="headings")
        self.terminal_tree.heading("Packet Number", text="Packet Number")
        self.terminal_tree.heading("Packet Size", text="Packet Size")
        self.terminal_tree.heading("Source", text="Source")
        self.terminal_tree.heading("Destination", text="Destination")
        self.terminal_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(terminal_frame, command=self.terminal_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.terminal_tree.config(yscrollcommand=scrollbar.set)

        self.load_terminal_data()

        self.create_config_ui()

        self.update_ui()

        self.mechagon.mainloop()

    def load_terminal_data(self):
        for i in self.terminal_tree.get_children():
            self.terminal_tree.delete(i)
        self.cursor.execute("SELECT Number, length, Source, Destination FROM 'data log'")
        for row in self.cursor.fetchall():
            self.terminal_tree.insert("", tk.END, values=(row[0], row[1], row[2], row[3]))

    def load_table_data(self, tree, table_name):
        for i in tree.get_children():
            tree.delete(i)
        self.cursor.execute(f"SELECT Source FROM {table_name}")
        for row in self.cursor.fetchall():
            tree.insert("", tk.END, values=(row[0],))

    def create_config_ui(self):
        mechagon_config = tk.Toplevel(master=self.mechagon, bg="#292929")
        mechagon_config.title("Mechagon Config")
        mechagon_config.geometry("420x200")
        mechagon_config.lift()

        frame4 = tk.Frame(master=mechagon_config, bg="#292929", height=76)
        frame4.pack(side=tk.BOTTOM, fill=tk.X)

        sizelimitselector = tk.Entry(master=frame4, bg="#ffffff", fg="#000")
        sizelimitselector.insert(0, str(self.size_limit))  # Set default size limit
        sizelimitselector.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        sizelimit = tk.Button(master=frame4, text="Update packet size limit", command=lambda: self.update_packet_size(sizelimitselector), bg="#5787e1", fg="#ffffff", font=("TkDefaultFont", 8), width=30, height=2)
        sizelimit.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        frame5 = tk.Frame(master=mechagon_config, bg="#292929", height=82)
        frame5.pack(side=tk.BOTTOM, fill=tk.X)

        interface_entry = tk.Entry(master=frame5, bg="#ffffff", fg="#000")
        interface_entry.insert(0, self.ethernet_port)  # Set current ethernet port
        interface_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        interface_btn = tk.Button(master=frame5, text="Update Ethernet Port", command=lambda: self.update_ethernet_port(interface_entry), bg="#5787e1", fg="#ffffff", font=("TkDefaultFont", 8), width=30, height=2)
        interface_btn.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        frame6 = tk.Frame(master=mechagon_config, bg="#57e187")
        frame6.pack(side=tk.BOTTOM, fill=tk.X)

        frame7 = tk.Frame(master=frame6, bg="#57e187")
        frame7.pack(side=tk.BOTTOM, fill=tk.X)

        excel = tk.Button(master=frame7, text="Export log to excel", command=lambda: self.export_to_excel(excel1), bg="#00b740", fg="#ffffff", font=("TkDefaultFont", 8), width=30, height=2)
        excel.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        excel1 = tk.Entry(master=frame7, bg="#fff", fg="#000")
        excel1.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        label1 = tk.Label(master=frame6, text="Warning this will purge any data in stored in the program!", bg="#57e187", fg="#000", anchor="center")
        label1.pack(side=tk.TOP, pady=10)

    def create_table_widget(self, parent, table_name):
        frame = tk.Frame(parent)
        frame.pack(side=tk.TOP)

        tree = ttk.Treeview(frame, columns=("address",), show='headings', height=10)
        tree.column("address", width=300)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.load_table_data(tree, table_name)

        entry = tk.Entry(frame)
        entry.pack(side=tk.TOP, padx=5, pady=5)

        def add_value():
            fw = FireWall()
            val = entry.get()
            if val:
                self.cursor.execute(f"INSERT INTO {table_name} (Source) VALUES (?)", (val,))
                self.conn.commit()
                self.load_table_data(tree, table_name)
                entry.delete(0, tk.END)
                if table_name == "BlackList":
                    fw.block_ip(val)
                

        def delete_value():
            selected = tree.selection()
            fw =FireWall()
            if selected:
                item_id = tree.item(selected)["values"][0]
                self.cursor.execute(f"DELETE FROM {table_name} WHERE Source = ?", (item_id,))
                self.conn.commit()
                self.load_table_data(tree, table_name)
                if table_name == "BlackList":
                    fw.unblock_ip(item_id)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side=tk.TOP)

        add_btn = tk.Button(btn_frame, text="Add", command=add_value, bg="#00b740", fg="#ffffff")
        add_btn.pack(side=tk.LEFT, padx=2)

        del_btn = tk.Button(btn_frame, text="Remove", command=delete_value, bg="#b80000", fg="#ffffff")
        del_btn.pack(side=tk.LEFT, padx=2)

        return tree

    def update_ui(self):
        self.load_terminal_data()
        self.mechagon.after(5000, self.update_ui)

    def update_packet_size(self, sizelimitselector):
        new_size_limit = sizelimitselector.get()
        if new_size_limit.isdigit():
            self.size_limit = int(new_size_limit)
            
            self.cursor.execute("UPDATE Constants SET Size_Limit = ? WHERE Ethernet_Port = ?", (self.size_limit, self.ethernet_port))
            self.conn.commit()
            
            print(f"New packet size limit: {self.size_limit}")
            

    def update_ethernet_port(self, interface_entry):
        new_ethernet_port = interface_entry.get()
        self.ethernet_port = new_ethernet_port
    
        self.cursor.execute("UPDATE Constants SET Ethernet_Port = ? WHERE Size_Limit = ?", (self.ethernet_port, self.size_limit))
        self.conn.commit()
        
        print(f"New Network interface: {self.ethernet_port}")
        

    def export_to_excel(self, excel):
        
        db = DataBase()
        new_excel_sheet = excel.get()

        if not new_excel_sheet.endswith('.xlsx'):
            new_excel_sheet = new_excel_sheet + '.xlsx'
        
        db.Resistance_Is_futile(new_excel_sheet)
        print(f"Database Purged as: {new_excel_sheet}")
        

if __name__ == "__main__":
    ui = User_Interface()
    ui.create_ui()