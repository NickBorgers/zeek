# Local site configuration for Zeek
# This file contains site-specific settings and custom monitoring rules

# Load the main configuration
@load /opt/zeek/etc/zeek-config.zeek

# Site-specific settings
redef Site::local_nets = {
    10.0.0.0/8,
    172.16.0.0/12,
    192.168.0.0/16,
    127.0.0.0/8,
};

# Configure log paths
redef Log::default_logdir = "/opt/zeek/logs";

# Enable JSON logging for better integration
redef Log::default_use_json = T;

# Configure log rotation
redef Log::default_rotation_interval = 1 hr;
redef Log::default_rotation_postprocessor_cmd = "gzip";

# Set up custom log streams for specific monitoring
module BroadcastMonitor;

export {
    # Custom log for broadcast traffic analysis
    redef enum Log::ID += { BROADCAST_LOG };
    
    # Record type for broadcast events
    type BroadcastEvent: record {
        ts: time;
        uid: string;
        src_ip: addr;
        dst_ip: addr;
        protocol: string;
        service: string;
        message: string;
        severity: string;
    };
}

# Initialize the broadcast monitoring
event zeek_init()
{
    Log::create_stream(BroadcastMonitor::BROADCAST_LOG, [$columns=BroadcastEvent]);
}

# Monitor for suspicious broadcast patterns
event connection_established(c: connection)
{
    # Check for broadcast traffic
    if ( c$id$resp_h in Site::local_nets && 
         (c$id$resp_h == 255.255.255.255 || 
          c$id$resp_h == 224.0.0.1 || 
          c$id$resp_h == 224.0.0.251) )
    {
        local info: BroadcastEvent;
        info$ts = network_time();
        info$uid = c$uid;
        info$src_ip = c$id$orig_h;
        info$dst_ip = c$id$resp_h;
        info$protocol = "broadcast";
        info$service = "unknown";
        info$message = fmt("Broadcast traffic detected from %s to %s", c$id$orig_h, c$id$resp_h);
        info$severity = "info";
        
        Log::write(BroadcastMonitor::BROADCAST_LOG, info);
    }
}

# Monitor for DHCP traffic
event dhcp_message(c: connection, is_orig: bool, msg: dhcp_msg, options: dhcp_opts)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "DHCP";
    info$service = "dhcp";
    info$message = fmt("DHCP %s from %s", msg$h_type, c$id$orig_h);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for mDNS traffic
event mdns_message(c: connection, is_orig: bool, msg: mdns_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "mDNS";
    info$service = "mdns";
    info$message = fmt("mDNS query: %s", msg$query);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for ARP traffic
event arp_request(c: connection, is_orig: bool, msg: arp_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "ARP";
    info$service = "arp";
    info$message = fmt("ARP request: %s -> %s", msg$src_mac, msg$dst_mac);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for NetBIOS traffic
event netbios_message(c: connection, is_orig: bool, msg: netbios_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "NetBIOS";
    info$service = "netbios";
    info$message = fmt("NetBIOS: %s", msg$name);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for LLMNR traffic
event llmnr_message(c: connection, is_orig: bool, msg: llmnr_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "LLMNR";
    info$service = "llmnr";
    info$message = fmt("LLMNR query: %s", msg$query);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for NTP traffic
event ntp_message(c: connection, is_orig: bool, msg: ntp_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "NTP";
    info$service = "ntp";
    info$message = fmt("NTP %s", msg$mode);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for SNMP traffic
event snmp_message(c: connection, is_orig: bool, msg: snmp_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "SNMP";
    info$service = "snmp";
    info$message = fmt("SNMP %s", msg$version);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for TFTP traffic
event tftp_message(c: connection, is_orig: bool, msg: tftp_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "TFTP";
    info$service = "tftp";
    info$message = fmt("TFTP %s: %s", msg$opcode, msg$filename);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for Syslog traffic
event syslog_message(c: connection, is_orig: bool, msg: syslog_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "Syslog";
    info$service = "syslog";
    info$message = fmt("Syslog: %s", msg$message);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for Modbus traffic
event modbus_message(c: connection, is_orig: bool, msg: modbus_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "Modbus";
    info$service = "modbus";
    info$message = fmt("Modbus %s", msg$function_code);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for DNP3 traffic
event dnp3_message(c: connection, is_orig: bool, msg: dnp3_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "DNP3";
    info$service = "dnp3";
    info$message = fmt("DNP3 %s", msg$function_code);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for BACnet traffic
event bacnet_message(c: connection, is_orig: bool, msg: bacnet_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "BACnet";
    info$service = "bacnet";
    info$message = fmt("BACnet %s", msg$service);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for SMB traffic
event smb_message(c: connection, is_orig: bool, msg: smb_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "SMB";
    info$service = "smb";
    info$message = fmt("SMB %s", msg$command);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Monitor for RDP traffic
event rdp_message(c: connection, is_orig: bool, msg: rdp_msg)
{
    local info: BroadcastEvent;
    info$ts = network_time();
    info$uid = c$uid;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$protocol = "RDP";
    info$service = "rdp";
    info$message = fmt("RDP %s", msg$type);
    info$severity = "info";
    
    Log::write(BroadcastMonitor::BROADCAST_LOG, info);
}

# Print startup message
event zeek_init()
{
    print "Local Zeek configuration loaded";
    print "Monitoring broadcast traffic and local network communications";
    print "Logs will be written to /opt/zeek/logs/";
} 