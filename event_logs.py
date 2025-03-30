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
import win32evtlog
import win32con
import win32security
import datetime
import json
import re

EVENT_ID_MAP = {
    # Account management events
    4720: "User account created",
    4722: "User account enabled",
    4723: "User password change attempt",
    4724: "Password reset attempt",
    4725: "User account disabled",
    4726: "User account deleted",
    4738: "User account changed",
    4740: "User account locked out",
    4767: "User account unlocked",
    4781: "User name changed",
    
    # Logon events
    4624: "Successful logon",
    4625: "Failed logon attempt",
    4634: "Account logoff",
    4647: "User initiated logoff",
    4648: "Explicit credential logon",
    4675: "SIDs were filtered",
    
    # Privilege use
    4672: "Special privileges assigned to new logon",
    4673: "Sensitive privilege use",
    4674: "Operation attempted using privileged object",
    
    # Policy changes
    4719: "System audit policy changed",
    4739: "Domain policy changed",
    
    # System events
    1074: "System shutdown",
    1102: "Audit log cleared",
    4608: "Windows starting up",
    4616: "System time changed",
    
    # Object access
    4656: "Object handle requested",
    4660: "Object deleted",
    4663: "Object access attempt",
    4670: "Permissions changed on object",
    
    # Process events
    4688: "Process created",
    4689: "Process exited",
    4696: "Primary token assigned to process"
}

def parse_event_data(event):
    """Parse the event data string into a structured format."""
    data = {}
    
    if not event.StringInserts:
        return data
    
    # Different event IDs have different data formats
    event_id = event.EventID & 0xFFFF  # Mask out flags
    
    if event_id in [4624, 4625]:  # Logon events
        keys = [
            "Subject.Security ID", "Subject.Account Name", "Subject.Account Domain",
            "Logon.Type", "New Logon.Security ID", "New Logon.Account Name",
            "New Logon.Account Domain", "Process.ID", "Process.Name",
            "Network.Address", "Network.Port"
        ]
        
        # Try to parse the event data
        try:
            for i, key in enumerate(keys):
                if i < len(event.StringInserts):
                    data[key] = event.StringInserts[i]
        except:
            pass
    
    # For unparsed event types, just include the raw data
    if not data and event.StringInserts:
        data["raw"] = event.StringInserts
    
    return data

def collect_security_events(hours=24, event_ids=None):
    """
    Collect security events from the Windows Event Log.
    
    Args:
        hours: Number of hours to look back
        event_ids: List of specific event IDs to collect, or None for all
    
    Returns:
        List of event dictionaries
    """
    events = []
    server = 'localhost'
    logtype = 'Security'
    
    # Calculate time filter
    time_filter = datetime.datetime.now() - datetime.timedelta(hours=hours)
    
    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        
        events_read = 0
        while events_read < total:
            events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
            
            if not events_batch:
                break
                
            for event in events_batch:
                # Extract event_id without flags
                event_id = event.EventID & 0xFFFF
                
                # Filter by event ID if specified
                if event_ids and event_id not in event_ids:
                    continue
                
                # Convert event time to datetime
                time_generated = datetime.datetime(
                    event.TimeGenerated.year,
                    event.TimeGenerated.month,
                    event.TimeGenerated.day,
                    event.TimeGenerated.hour,
                    event.TimeGenerated.minute,
                    event.TimeGenerated.second
                )
                
                # Skip events older than our filter
                if time_generated < time_filter:
                    continue
                
                # Parse event data
                event_data = parse_event_data(event)
                
                # Add basic event info
                event_record = {
                    'EventID': event_id,
                    'Time': time_generated.strftime('%Y-%m-%d %H:%M:%S'),
                    'Source': event.SourceName,
                    'Category': event.EventCategory,
                    'Type': event.EventType,
                    'Description': EVENT_ID_MAP.get(event_id, "Unknown event"),
                    'Data': event_data
                }
                
                events.append(event_record)
                    
            events_read += len(events_batch)
                
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        events.append({'Error': str(e)})
        
    return events

def find_suspicious_events(events):
    """
    Analyze events for suspicious activities.
    
    Args:
        events: List of event dictionaries
    
    Returns:
        List of suspicious events with risk assessment
    """
    suspicious = []
    
    # Track login failures
    failed_logins = {}
    admin_logins = []
    
    for event in events:
        event_id = event.get('EventID')
        
        # Failed login attempts (brute force)
        if event_id == 4625:
            account = event.get('Data', {}).get('New Logon.Account Name')
            ip = event.get('Data', {}).get('Network.Address')
            
            if account and ip:
                key = f"{account}|{ip}"
                failed_logins[key] = failed_logins.get(key, 0) + 1
                
                if failed_logins[key] >= 5:
                    suspicious.append({
                        'severity': 'high',
                        'category': 'Possible Brute Force',
                        'description': f"Multiple failed login attempts for account '{account}' from IP {ip}",
                        'event': event
                    })
        
        # Admin account logins
        elif event_id == 4624:
            account = event.get('Data', {}).get('New Logon.Account Name', '').lower()
            domain = event.get('Data', {}).get('New Logon.Account Domain', '').lower()
            
            # Look for admin account usage
            if account in ['administrator', 'admin'] or 'admin' in account:
                admin_logins.append(event)
                suspicious.append({
                    'severity': 'medium',
                    'category': 'Admin Account Usage',
                    'description': f"Admin account '{domain}\\{account}' was used to log in",
                    'event': event
                })
        
        # Audit log cleared (possible cover-up)
        elif event_id == 1102:
            suspicious.append({
                'severity': 'high',
                'category': 'Evidence Tampering',
                'description': "Security audit log was cleared",
                'event': event
            })
        
        # User account created
        elif event_id == 4720:
            suspicious.append({
                'severity': 'medium',
                'category': 'Account Management',
                'description': f"New user account created: {event.get('Data', {}).get('New Account.Account Name', 'Unknown')}",
                'event': event
            })
        
        # System time changed
        elif event_id == 4616:
            suspicious.append({
                'severity': 'medium',
                'category': 'System Integrity',
                'description': "System time was changed",
                'event': event
            })
        
        # Special privileges assigned
        elif event_id == 4672:
            account = event.get('Data', {}).get('Subject.Account Name')
            if account and account.lower() not in ['system', 'local service', 'network service']:
                suspicious.append({
                    'severity': 'medium',
                    'category': 'Privilege Escalation',
                    'description': f"Special privileges assigned to {account}",
                    'event': event
                })
    
    return suspicious

def run(hours=24):
    """Run the Windows Event Log audit module."""
    all_events = collect_security_events(hours)
    suspicious = find_suspicious_events(all_events)
    
    return {
        "Event Log Summary": {
            "Total Events": len(all_events),
            "Suspicious Events": len(suspicious)
        },
        "Suspicious Activities": suspicious,
        "Recent Events": all_events[:100],  # Limit to most recent 100 events
        "_risks": [
            {
                "severity": item["severity"],
                "category": item["category"],
                "description": item["description"]
            } for item in suspicious
        ]
    }
