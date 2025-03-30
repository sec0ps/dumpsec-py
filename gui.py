# =============================================================================
# DumpSec-Py - Windows Security Auditing Tool
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script is part of the DumpSec-Py tool, which is designed to
#          perform detailed security audits on Windows systems. It covers
#          user rights, services, registry permissions, file/share permissions,
#          group policy enumeration, risk assessments, and more.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, 
                            QVBoxLayout, QHBoxLayout, QWidget, QPushButton, 
                            QTextEdit, QLabel, QComboBox, QTableWidget, 
                            QTableWidgetItem, QProgressBar, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import json
import os

class AuditWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    
    def __init__(self, modules):
        super().__init__()
        self.modules = modules
    
    def run(self):
        results = {}
        module_count = len(self.modules)
        
        for i, (name, func) in enumerate(self.modules.items()):
            try:
                results[name] = func()
                self.progress.emit(int((i + 1) / module_count * 100))
            except Exception as e:
                results[name] = {"Error": str(e)}
        
        self.finished.emit(results)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("DumpSec-Py Security Auditor")
        self.setMinimumSize(800, 600)
        
        # Main layout
        main_layout = QVBoxLayout()
        
        # Control bar
        control_layout = QHBoxLayout()
        
        # Run button
        self.run_button = QPushButton("Run Audit")
        self.run_button.clicked.connect(self.run_audit)
        control_layout.addWidget(self.run_button)
        
        # Module selection
        self.module_selector = QComboBox()
        self.module_selector.addItem("All Modules")
        self.module_selector.addItem("Users and Groups")
        self.module_selector.addItem("File and Share Permissions")
        self.module_selector.addItem("Registry Permissions")
        self.module_selector.addItem("Services and Tasks")
        self.module_selector.addItem("Local Security Policy")
        self.module_selector.addItem("Domain Trusts and Sessions")
        control_layout.addWidget(self.module_selector)
        
        # Export button
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        control_layout.addWidget(self.export_button)
        
        main_layout.addLayout(control_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # Tab widget for results
        self.tabs = QTabWidget()
        
        # Summary tab
        self.summary_tab = QWidget()
        summary_layout = QVBoxLayout()
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        summary_layout.addWidget(self.summary_text)
        self.summary_tab.setLayout(summary_layout)
        self.tabs.addTab(self.summary_tab, "Summary")
        
        # Findings tab
        self.findings_tab = QWidget()
        findings_layout = QVBoxLayout()
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(3)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Category", "Description"])
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        findings_layout.addWidget(self.findings_table)
        self.findings_tab.setLayout(findings_layout)
        self.tabs.addTab(self.findings_tab, "Findings")
        
        # Details tab
        self.details_tab = QWidget()
        details_layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        self.details_tab.setLayout(details_layout)
        self.tabs.addTab(self.details_tab, "Raw Data")
        
        main_layout.addWidget(self.tabs)
        
        # Central widget
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        # Initialize data
        self.results = {}
        self.module_map = {
            "Users and Groups": "user_groups",
            "File and Share Permissions": "file_shares",
            "Registry Permissions": "registry_audit",
            "Services and Tasks": "services_tasks",
            "Local Security Policy": "local_policy",
            "Domain Trusts and Sessions": "domain_info"
        }
    
    def run_audit(self):
        # Disable buttons during audit
        self.run_button.setEnabled(False)
        self.export_button.setEnabled(False)
        
        selected = self.module_selector.currentText()
        
        # Import required modules
        from user_groups import run as run_user_groups
        from file_shares import run as run_file_shares
        from registry_audit import run as run_registry_audit
        from services_tasks import run as run_services_tasks
        from local_policy import run as run_local_policy
        from domain_info import run as run_domain_info
        
        modules = {
            "Users and Groups": run_user_groups,
            "File and Share Permissions": run_file_shares,
            "Registry Permissions": run_registry_audit,
            "Services and Tasks": run_services_tasks,
            "Local Security Policy": run_local_policy,
            "Domain Trusts and Sessions": run_domain_info
        }
        
        if selected == "All Modules":
            selected_modules = modules
        else:
            selected_modules = {selected: modules[selected]}
        
        # Create and start worker thread
        self.worker = AuditWorker(selected_modules)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.process_results)
        self.worker.start()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def process_results(self, results):
        self.results = results
        
        # Update summary tab
        self.update_summary()
        
        # Update findings tab
        self.update_findings()
        
        # Update details tab
        self.update_details()
        
        # Re-enable buttons
        self.run_button.setEnabled(True)
        self.export_button.setEnabled(True)
    
    def update_summary(self):
        summary = []
        
        # Count all risks
        total_risks = 0
        risk_by_severity = {"high": 0, "medium": 0, "low": 0}
        
        for module, data in self.results.items():
            risks = data.get("_risks", [])
            total_risks += len(risks)
            
            for risk in risks:
                severity = risk.get("severity", "").lower()
                if severity in risk_by_severity:
                    risk_by_severity[severity] += 1
        
        # Create HTML summary
        summary.append("<h2>Audit Summary</h2>")
        summary.append(f"<p>Total findings: {total_risks}</p>")
        summary.append("<ul>")
        summary.append(f"<li><span style='color:red;font-weight:bold;'>High</span>: {risk_by_severity['high']}</li>")
        summary.append(f"<li><span style='color:orange;font-weight:bold;'>Medium</span>: {risk_by_severity['medium']}</li>")
        summary.append(f"<li><span style='color:blue;font-weight:bold;'>Low</span>: {risk_by_severity['low']}</li>")
        summary.append("</ul>")
        
        # Module details
        for module, data in self.results.items():
            module_risks = data.get("_risks", [])
            summary.append(f"<h3>{module}</h3>")
            summary.append(f"<p>Findings: {len(module_risks)}</p>")
        
        self.summary_text.setHtml("\n".join(summary))
    
    def update_findings(self):
        all_risks = []
        
        for module, data in self.results.items():
            risks = data.get("_risks", [])
            all_risks.extend(risks)
        
        # Sort risks by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        all_risks.sort(key=lambda x: severity_order.get(x.get("severity", "").lower(), 3))
        
        # Update table
        self.findings_table.setRowCount(len(all_risks))
        
        for i, risk in enumerate(all_risks):
            # Set table items
            severity_item = QTableWidgetItem(risk.get("severity", "").upper())
            if risk.get("severity", "").lower() == "high":
                severity_item.setBackground(Qt.red)
                severity_item.setForeground(Qt.white)
            elif risk.get("severity", "").lower() == "medium":
                severity_item.setBackground(Qt.yellow)
            
            self.findings_table.setItem(i, 0, severity_item)
            self.findings_table.setItem(i, 1, QTableWidgetItem(risk.get("category", "")))
            self.findings_table.setItem(i, 2, QTableWidgetItem(risk.get("description", "")))
    
    def update_details(self):
        self.details_text.setText(json.dumps(self.results, indent=2))
    
    def export_results(self):
        if not self.results:
            return
        
        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "", 
            "JSON Files (*.json);;CSV Files (*.csv);;HTML Files (*.html);;PDF Files (*.pdf);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Determine format from extension
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == ".json":
            with open(file_path, "w") as f:
                json.dump(self.results, f, indent=2)
        elif ext == ".csv":
            # Import report_writer module
            from report_writer import write_csv
            write_csv(self.results, file_path)
        elif ext == ".html":
            # Import report_writer module
            from report_writer import write_html
            write_html(self.results, file_path)
        elif ext == ".pdf":
            # Import report_writer module
            from report_writer import write_pdf
            write_pdf(self.results, file_path)
        else:
            # Default to JSON
            with open(file_path, "w") as f:
                json.dump(self.results, f, indent=2)
