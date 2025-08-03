# Comprehensive Zeek configuration for network monitoring
# This configuration enables all plugins and sets up monitoring for:
# - Broadcast traffic
# - mDNS (multicast DNS)
# - DHCP
# - ARP
# - NetBIOS
# - LLMNR
# - NTP
# - SNMP
# - And other local network protocols

# Load all available plugins
@load zeek-plugin-arp
@load zeek-plugin-dhcp
@load zeek-plugin-mdns
@load zeek-plugin-netbios
@load zeek-plugin-llmnr
@load zeek-plugin-ntp
@load zeek-plugin-snmp
@load zeek-plugin-tftp
@load zeek-plugin-syslog
@load zeek-plugin-modbus
@load zeek-plugin-dnp3
@load zeek-plugin-bacnet
@load zeek-plugin-smb
@load zeek-plugin-rdp

# Load additional useful protocols
@load protocols/conn
@load protocols/dns
@load protocols/http
@load protocols/ssl
@load protocols/ftp
@load protocols/smtp
@load protocols/ssh
@load protocols/irc
@load protocols/ntlm
@load protocols/smb
@load protocols/dce-rpc
@load protocols/rdp
@load protocols/sip
@load protocols/radius
@load protocols/ldap
@load protocols/krb
@load protocols/nfs
@load protocols/snmp
@load protocols/tftp
@load protocols/dhcp
@load protocols/ntp
@load protocols/irc
@load protocols/ssl
@load protocols/ssh
@load protocols/smtp
@load protocols/ftp
@load protocols/http
@load protocols/dns
@load protocols/conn

# Load analysis scripts
@load base/frameworks/notice
@load base/frameworks/input
@load base/frameworks/sumstats
@load base/frameworks/logging
@load base/frameworks/files
@load base/frameworks/software
@load base/frameworks/communication
@load base/frameworks/reporter
@load base/frameworks/intel
@load base/frameworks/signatures
@load base/frameworks/cluster

# Load policy scripts
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/irc
@load base/protocols/ntlm
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/rdp
@load base/protocols/sip
@load base/protocols/radius
@load base/protocols/ldap
@load base/protocols/krb
@load base/protocols/nfs
@load base/protocols/snmp
@load base/protocols/tftp
@load base/protocols/dhcp
@load base/protocols/ntp

# Configure logging
redef Log::default_rotation_interval = 1 hr;
redef Log::default_mv_to_stderr = T;
redef Log::default_use_json = T;

# Configure connection logging
redef Conn::log_passive = T;
redef Conn::log_active = T;

# Configure DNS logging
redef DNS::log_passive = T;
redef DNS::log_active = T;

# Configure HTTP logging
redef HTTP::log_passive = T;
redef HTTP::log_active = T;

# Configure SSL logging
redef SSL::log_passive = T;
redef SSL::log_active = T;

# Configure DHCP logging
redef DHCP::log_passive = T;
redef DHCP::log_active = T;

# Configure SNMP logging
redef SNMP::log_passive = T;
redef SNMP::log_active = T;

# Configure NTP logging
redef NTP::log_passive = T;
redef NTP::log_active = T;

# Configure TFTP logging
redef TFTP::log_passive = T;
redef TFTP::log_active = T;

# Configure SMB logging
redef SMB::log_passive = T;
redef SMB::log_active = T;

# Configure RDP logging
redef RDP::log_passive = T;
redef RDP::log_active = T;

# Configure Syslog logging
redef Syslog::log_passive = T;
redef Syslog::log_active = T;

# Configure Modbus logging
redef Modbus::log_passive = T;
redef Modbus::log_active = T;

# Configure DNP3 logging
redef DNP3::log_passive = T;
redef DNP3::log_active = T;

# Configure BACnet logging
redef BACnet::log_passive = T;
redef BACnet::log_active = T;

# Configure ARP logging
redef ARP::log_passive = T;
redef ARP::log_active = T;

# Configure mDNS logging
redef MDNS::log_passive = T;
redef MDNS::log_active = T;

# Configure NetBIOS logging
redef NetBIOS::log_passive = T;
redef NetBIOS::log_active = T;

# Configure LLMNR logging
redef LLMNR::log_passive = T;
redef LLMNR::log_active = T;

# Set up file analysis
redef Files::log_passive = T;
redef Files::log_active = T;

# Configure software detection
redef Software::log_passive = T;
redef Software::log_active = T;

# Configure communication framework
redef Communication::nodes = {
    ["manager"] = [$host=127.0.0.1, $p=47760/tcp, $zone_id="manager"],
    ["worker-1"] = [$host=127.0.0.1, $p=47761/tcp, $zone_id="worker-1", $interface="eth0"],
};

# Configure cluster settings
redef Cluster::manager = [$host=127.0.0.1, $p=47760/tcp];
redef Cluster::workers = {
    ["worker-1"] = [$host=127.0.0.1, $p=47761/tcp, $interface="eth0"],
};

# Configure signature framework
redef Signatures::log_passive = T;
redef Signatures::log_active = T;

# Configure intelligence framework
redef Intel::log_passive = T;
redef Intel::log_active = T;

# Configure reporter framework
redef Reporter::log_passive = T;
redef Reporter::log_active = T;

# Configure notice framework
redef Notice::log_passive = T;
redef Notice::log_active = T;

# Configure sumstats framework
redef SumStats::log_passive = T;
redef SumStats::log_active = T;

# Configure input framework
redef Input::log_passive = T;
redef Input::log_active = T;

# Set up custom logging for broadcast traffic
event zeek_init()
{
    # Create custom log for broadcast traffic
    local broadcast_log = Log::get_stream_id("broadcast");
    if ( broadcast_log == Log::NO_STREAM_ID )
    {
        Log::create_stream(Log::ID("broadcast"), [$columns=BroadcastInfo]);
    }
}

# Define custom log structure for broadcast traffic
type BroadcastInfo: record {
    ts: time;
    uid: string;
    id: conn_id;
    proto: string;
    src_ip: addr;
    dst_ip: addr;
    src_port: port;
    dst_port: port;
    service: string;
    message: string;
};

# Event to log broadcast traffic
event broadcast_detected(c: connection, proto: string, service: string, message: string)
{
    local info: BroadcastInfo;
    info$ts = network_time();
    info$uid = c$uid;
    info$id = c$id;
    info$proto = proto;
    info$src_ip = c$id$orig_h;
    info$dst_ip = c$id$resp_h;
    info$src_port = c$id$orig_p;
    info$dst_port = c$id$resp_p;
    info$service = service;
    info$message = message;
    
    Log::write(Log::ID("broadcast"), info);
}

# Hook for DHCP events
event dhcp_message(c: connection, is_orig: bool, msg: dhcp_msg, options: dhcp_opts)
{
    if ( is_orig )
    {
        local message = fmt("DHCP %s from %s", msg$h_type, c$id$orig_h);
        event broadcast_detected(c, "DHCP", "dhcp", message);
    }
}

# Hook for mDNS events
event mdns_message(c: connection, is_orig: bool, msg: mdns_msg)
{
    if ( is_orig )
    {
        local message = fmt("mDNS query: %s", msg$query);
        event broadcast_detected(c, "mDNS", "mdns", message);
    }
}

# Hook for ARP events
event arp_request(c: connection, is_orig: bool, msg: arp_msg)
{
    if ( is_orig )
    {
        local message = fmt("ARP request: %s -> %s", msg$src_mac, msg$dst_mac);
        event broadcast_detected(c, "ARP", "arp", message);
    }
}

# Hook for NetBIOS events
event netbios_message(c: connection, is_orig: bool, msg: netbios_msg)
{
    if ( is_orig )
    {
        local message = fmt("NetBIOS: %s", msg$name);
        event broadcast_detected(c, "NetBIOS", "netbios", message);
    }
}

# Hook for LLMNR events
event llmnr_message(c: connection, is_orig: bool, msg: llmnr_msg)
{
    if ( is_orig )
    {
        local message = fmt("LLMNR query: %s", msg$query);
        event broadcast_detected(c, "LLMNR", "llmnr", message);
    }
}

# Hook for NTP events
event ntp_message(c: connection, is_orig: bool, msg: ntp_msg)
{
    if ( is_orig )
    {
        local message = fmt("NTP %s", msg$mode);
        event broadcast_detected(c, "NTP", "ntp", message);
    }
}

# Hook for SNMP events
event snmp_message(c: connection, is_orig: bool, msg: snmp_msg)
{
    if ( is_orig )
    {
        local message = fmt("SNMP %s", msg$version);
        event broadcast_detected(c, "SNMP", "snmp", message);
    }
}

# Hook for TFTP events
event tftp_message(c: connection, is_orig: bool, msg: tftp_msg)
{
    if ( is_orig )
    {
        local message = fmt("TFTP %s: %s", msg$opcode, msg$filename);
        event broadcast_detected(c, "TFTP", "tftp", message);
    }
}

# Hook for Syslog events
event syslog_message(c: connection, is_orig: bool, msg: syslog_msg)
{
    if ( is_orig )
    {
        local message = fmt("Syslog: %s", msg$message);
        event broadcast_detected(c, "Syslog", "syslog", message);
    }
}

# Hook for Modbus events
event modbus_message(c: connection, is_orig: bool, msg: modbus_msg)
{
    if ( is_orig )
    {
        local message = fmt("Modbus %s", msg$function_code);
        event broadcast_detected(c, "Modbus", "modbus", message);
    }
}

# Hook for DNP3 events
event dnp3_message(c: connection, is_orig: bool, msg: dnp3_msg)
{
    if ( is_orig )
    {
        local message = fmt("DNP3 %s", msg$function_code);
        event broadcast_detected(c, "DNP3", "dnp3", message);
    }
}

# Hook for BACnet events
event bacnet_message(c: connection, is_orig: bool, msg: bacnet_msg)
{
    if ( is_orig )
    {
        local message = fmt("BACnet %s", msg$service);
        event broadcast_detected(c, "BACnet", "bacnet", message);
    }
}

# Hook for SMB events
event smb_message(c: connection, is_orig: bool, msg: smb_msg)
{
    if ( is_orig )
    {
        local message = fmt("SMB %s", msg$command);
        event broadcast_detected(c, "SMB", "smb", message);
    }
}

# Hook for RDP events
event rdp_message(c: connection, is_orig: bool, msg: rdp_msg)
{
    if ( is_orig )
    {
        local message = fmt("RDP %s", msg$type);
        event broadcast_detected(c, "RDP", "rdp", message);
    }
}

# Print loaded plugins on startup
event zeek_init()
{
    print "Zeek initialized with comprehensive plugin support";
    print "Loaded plugins for: ARP, DHCP, mDNS, NetBIOS, LLMNR, NTP, SNMP, TFTP, Syslog, Modbus, DNP3, BACnet, SMB, RDP";
    print "Monitoring broadcast traffic and local network communications";
} 