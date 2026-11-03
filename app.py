"""College incident-response dashboard. All containment actions are simulated."""
import json
from pathlib import Path
import sqlite3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from engine import Platform, read_alerts


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Incident Response Automation | College Project')
        self.geometry('1180x780'); self.minsize(920,620)
        self.platform = Platform()
        self.status = tk.StringVar(value='Import sample alerts to begin. All containment is simulated.')
        self.counts = tk.StringVar()
        style=ttk.Style(self); style.theme_use('clam')
        style.configure('TButton',padding=8)
        style.configure('Treeview',rowheight=28)
        head=tk.Frame(self,bg='#172e49',padx=20,pady=18); head.pack(fill='x')
        tk.Label(head,text='INCIDENT RESPONSE AUTOMATION',font=('Arial',21,'bold'),bg='#172e49',fg='white').pack(anchor='w')
        tk.Label(head,text='EDUCATIONAL SIMULATION  |  No external systems are changed',font=('Arial',11),bg='#172e49',fg='#ffd68a').pack(anchor='w',pady=(8,0))
        body=ttk.Frame(self,padding=16); body.pack(fill='both',expand=True)
        bar=ttk.Frame(body); bar.pack(fill='x')
        commands=[('Load sample alerts',self.samples),('Import JSON',self.import_file),
                  ('Approve simulation',self.approve),('Close incident',self.resolve),
                  ('Export CSV',self.export),('Refresh',self.refresh)]
        for label,fn in commands:
            ttk.Button(bar,text=label,command=fn).pack(side='left',padx=(0,6))
        ttk.Label(body,textvariable=self.counts,font=('Arial',11,'bold')).pack(anchor='w',pady=12)
        panes=ttk.Panedwindow(body,orient='vertical'); panes.pack(fill='both',expand=True)
        top=ttk.Frame(panes); bottom=ttk.Frame(panes); panes.add(top,weight=1); panes.add(bottom,weight=1)
        self.tree=ttk.Treeview(top,columns=('id','severity','title','status'),show='headings',selectmode='browse',height=8)
        for key,label,width in [('id','ID',60),('severity','Severity',110),('title','Incident',340),('status','Workflow status',260)]:
            self.tree.heading(key,text=label); self.tree.column(key,width=width,minwidth=60)
        scroll=ttk.Scrollbar(top,orient='vertical',command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set); self.tree.pack(side='left',fill='both',expand=True); scroll.pack(side='right',fill='y')
        for severity,color in [('CRITICAL','#ffe0e0'),('HIGH','#ffedcb'),('MEDIUM','#e6effd'),('LOW','#e2f2e7')]:
            self.tree.tag_configure(severity,background=color)
        self.tree.bind('<<TreeviewSelect>>',lambda event:self.detail())
        ttk.Label(bottom,text='Selected incident • supplied alert, actions and audit timeline').pack(anchor='w',pady=(10,6))
        self.text=tk.Text(bottom,wrap='word',font=('Consolas',10),height=12,state='disabled')
        detail_scroll=ttk.Scrollbar(bottom,orient='vertical',command=self.text.yview)
        self.text.configure(yscrollcommand=detail_scroll.set); self.text.pack(side='left',fill='both',expand=True); detail_scroll.pack(side='right',fill='y')
        ttk.Label(body,textvariable=self.status,wraplength=1100).pack(anchor='w',pady=(10,0))
        self.protocol('WM_DELETE_WINDOW',self.quit_app)
        self.refresh()

    def attempt(self,fn):
        try: return fn()
        except (OSError,ValueError,sqlite3.Error) as error:
            messagebox.showerror('Operation failed',str(error)); self.status.set('Operation failed: '+str(error))

    def selected(self):
        ids=self.tree.selection()
        if not ids: raise ValueError('Select an incident first.')
        return int(ids[0])

    def refresh(self):
        old=self.tree.selection()
        rows=self.platform.list_incidents()
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            self.tree.insert('', 'end',iid=str(row['id']),values=(row['id'],row['severity'],row['title'],row['status']),tags=(row['severity'],))
        self.counts.set(f"Total: {len(rows)}    |    Waiting approval: {sum(r['status']=='WAITING_APPROVAL' for r in rows)}    |    Closed: {sum(r['status']=='CLOSED' for r in rows)}")
        if old and self.tree.exists(old[0]): self.tree.selection_set(old[0])
        elif rows: self.tree.selection_set(str(rows[0]['id']))
        self.detail()

    def detail(self):
        ids=self.tree.selection()
        value=json.dumps(self.platform.detail(int(ids[0])),indent=2,ensure_ascii=False) if ids else 'No incidents. Load sample alerts to begin.'
        self.text.configure(state='normal'); self.text.delete('1.0','end'); self.text.insert('1.0',value); self.text.configure(state='disabled')

    def load(self,path):
        def operation():
            result=self.platform.ingest(read_alerts(path)); self.refresh()
            added=sum(not r['duplicate'] for r in result)
            self.status.set(f'Imported {added} new incidents; {len(result)-added} duplicate alerts skipped. Playbooks prepared automatically.')
        self.attempt(operation)

    def samples(self): self.load(Path(__file__).parent/'sample_data'/'alerts.json')

    def import_file(self):
        path=filedialog.askopenfilename(filetypes=[('JSON alerts','*.json')])
        if path: self.load(path)

    def approve(self):
        def operation():
            incident_id=self.selected()
            note=simpledialog.askstring('Approve simulated containment','Enter your review note. This runs only a local simulation.',parent=self)
            if note is None:return
            self.platform.approve(incident_id,note); self.refresh()
            self.status.set(f'Incident {incident_id}: simulation completed. No external system was changed.')
        self.attempt(operation)

    def resolve(self):
        def operation():
            incident_id=self.selected()
            note=simpledialog.askstring('Close incident','Enter a closure note explaining your review:',parent=self)
            if note is None:return
            self.platform.resolve(incident_id,note); self.refresh()
            self.status.set(f'Incident {incident_id} closed with a review note.')
        self.attempt(operation)

    def export(self):
        path=filedialog.asksaveasfilename(defaultextension='.csv',initialfile='incident_report.csv',filetypes=[('CSV report','*.csv')])
        if path:
            def operation():
                self.platform.export(path); self.status.set('Incident summary exported to '+path)
            self.attempt(operation)

    def quit_app(self):
        self.platform.close_connection(); self.destroy()

if __name__=='__main__':
    App().mainloop()
