import requests
import yaml
import sys
import os
import logging
from flask import Flask, Response, request

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
config_file = None

def convert_proxy(proxy_config):
    """Convert a single proxy configuration from Clash to Loon format"""
    logger.debug(f"Converting proxy config: {proxy_config}")
    
    if isinstance(proxy_config, str):
        logger.debug(f"Proxy config is string, returning directly: {proxy_config}")
        return proxy_config
        
    proxy_type = proxy_config.get('type', '').lower()
    name = proxy_config.get('name', '')
    server = proxy_config.get('server', '')
    port = proxy_config.get('port', '')
    
    logger.debug(f"Proxy type: {proxy_type}, name: {name}, server: {server}, port: {port}")
    
    if proxy_type == 'ss':
        cipher = proxy_config.get('cipher', '')
        password = proxy_config.get('password', '')
        result = f"{name} = shadowsocks,{server},{port},{cipher},\"{password}\""
        logger.debug(f"Converted SS proxy: {result}")
        
    elif proxy_type == 'ssr':
        cipher = proxy_config.get('cipher', '')
        password = proxy_config.get('password', '')
        protocol = proxy_config.get('protocol', '')
        protocol_param = proxy_config.get('protocol-param', '')
        obfs = proxy_config.get('obfs', '')
        obfs_param = proxy_config.get('obfs-param', '')
        result = f"{name} = shadowsocksr,{server},{port},{cipher},\"{password}\",{protocol},{protocol_param},{obfs},{obfs_param}"
        logger.debug(f"Converted SSR proxy: {result}")
        
    elif proxy_type == 'vmess':
        uuid = proxy_config.get('uuid', '')
        alterId = proxy_config.get('alterId', '0')
        cipher = proxy_config.get('cipher', 'auto')
        tls = ',over-tls=true' if proxy_config.get('tls', False) else ''
        transport = proxy_config.get('network', '')
        if transport == 'ws':
            ws_opts = proxy_config.get('ws-opts', {})
            path = f",ws-path={ws_opts.get('path', '')}"
        elif transport == 'grpc':
            grpc_opts = proxy_config.get('grpc-opts', {})
            if 'grpc-service-name' in grpc_opts:
                path = f",grpc-service-name={grpc_opts['grpc-service-name']}"
            else:
                path = ""
        else:
            path = ""
        result = f"{name} = vmess,{server},{port},{cipher},\"{uuid}\",{alterId}{tls}{path}"
        logger.debug(f"Converted VMess proxy: {result}")
        
    elif proxy_type == 'vless':
        uuid = proxy_config.get('uuid', '')
        transport = proxy_config.get('network', '')
        tls = ',tls=true' if proxy_config.get('tls', False) else ''
        result = f"{name} = vless,{server},{port},\"{uuid}\",transport={transport}{tls}"
        if transport == 'ws':
            ws_opts = proxy_config.get('ws-opts', {})
            result += f",ws-path={ws_opts.get('path', '')}"
        elif transport == 'grpc':
            grpc_opts = proxy_config.get('grpc-opts', {})
            if 'grpc-service-name' in grpc_opts:
                result += f",grpc-service-name={grpc_opts['grpc-service-name']}"
        if 'dialer-proxy' in proxy_config:
            result += f",underlying-proxy={proxy_config['dialer-proxy']}"
        logger.debug(f"Converted VLESS proxy: {result}")

    elif proxy_type == 'trojan':
        password = proxy_config.get('password', '')
        sni = proxy_config.get('sni', '')
        skip_cert_verify = ',skip-cert-verify=true' if proxy_config.get('skip-cert-verify', False) else ''
        result = f"{name} = trojan,{server},{port},{password},tls=true,sni={sni}{skip_cert_verify}"
        logger.debug(f"Converted Trojan proxy: {result}")

    elif proxy_type == 'wireguard':
        private_key = proxy_config.get('private-key', '')
        peer_public_key = proxy_config.get('peer-public-key', '')
        pre_shared_key = proxy_config.get('pre-shared-key', '')
        ip = proxy_config.get('ip', '')
        ipv6 = proxy_config.get('ipv6', '')
        result = f"{name} = wireguard,{server},{port},{private_key},{peer_public_key},{pre_shared_key},{ip},{ipv6}"
        logger.debug(f"Converted WireGuard proxy: {result}")

    elif proxy_type == 'hysteria2':
        password = proxy_config.get('password', '')
        sni = proxy_config.get('sni', '')
        skip_cert_verify = ',skip-cert-verify=true' if proxy_config.get('skip-cert-verify', False) else ''
        result = f"{name} = hysteria2,{server},{port},{password},sni={sni}{skip_cert_verify}"
        logger.debug(f"Converted Hysteria2 proxy: {result}")
            
    else:
        logger.warning(f"Unsupported proxy type: {proxy_type}")
        return None
        
    if 'dialer-proxy' in proxy_config:
        result += f",underlying-proxy={proxy_config['dialer-proxy']}"
        
    return result

def convert_proxy_groups(groups, proxies):
    """Convert proxy groups from Clash to Loon format"""
    logger.debug(f"Converting proxy groups: {groups}")
    result = []
    
    for group in groups:
        name = group.get('name', '')
        group_type = group.get('type', '').lower()
        logger.debug(f"Converting group: {name}, type: {group_type}")
        
        # Get proxies from both 'proxies' and 'use' fields
        group_proxies = group.get('proxies', [])
        use_providers = group.get('use', [])
        group_proxies += use_providers
        
        if group_type == 'select':
            proxies_str = ','.join(group_proxies)
            result.append(f"{name} = select,{proxies_str}")
            logger.debug(f"Converted select group: {name}")
            
        elif group_type in ['url-test', 'fallback']:
            proxies_str = ','.join(group_proxies)
            url = group.get('url', 'https://www.google.com/generate_204')
            interval = group.get('interval', 300)
            result.append(f"{name} = {group_type},{proxies_str},url={url},interval={interval}")
            logger.debug(f"Converted {group_type} group: {name}")
            
    return result

def convert_proxy_providers(proxy_providers):
    """Convert proxy providers from Clash to Loon format"""
    logger.debug(f"Converting proxy providers: {proxy_providers}")
    result = []
    
    if not proxy_providers:
        logger.debug("No proxy providers to convert")
        return result
        
    for name, provider in proxy_providers.items():
        url = provider.get('url', '')
        if url:
            # Add proxy provider parameters
            params = []
            if provider.get('udp'):
                params.append('udp=true')
            if provider.get('fast-open') is False:
                params.append('fast-open=false')
            if provider.get('vmess-aead'):
                params.append('vmess-aead=true')
            if provider.get('enabled', True):
                params.append('enabled=true')
            if provider.get('img-url'):
                params.append(f"img-url={provider['img-url']}")
                
            param_str = ','.join(params)
            if param_str:
                result.append(f"{name} = {url},{param_str}")
            else:
                result.append(f"{name} = {url}")
            logger.debug(f"Converted proxy provider: {name}")
                
    return result

def convert_rules(rules):
    """Convert rules from Clash to Loon format"""
    logger.debug(f"Converting rules: {rules}")
    result = []
    
    for rule in rules:
        if rule.startswith('RULE-SET'):
            continue
        if isinstance(rule, str):
            parts = rule.split(',')
            if len(parts) >= 2:
                if parts[0] == 'MATCH':
                    parts[0] = 'FINAL'
                result.append(','.join(parts))
                logger.debug(f"Converted rule: {','.join(parts)}")
                
    return result

def convert_rule_providers(rule_providers, rules):
    """Convert rule providers from Clash to Loon format"""
    logger.debug(f"Converting rule providers: {rule_providers}")
    result = []
    
    if not rule_providers:
        logger.debug("No rule providers to convert")
        return result
        
    rule_provider_policies = {}
    for rule in rules:
        if rule.startswith('RULE-SET'):
            parts = rule.split(',')
            if len(parts) == 3:
                rule_provider_policies[parts[1]] = parts[2]
    
    for name, provider in rule_providers.items():
        url = provider.get('url', '')
        if url:
            policy = rule_provider_policies.get(name)
            if policy is None:
                continue
            result.append(f"{url},policy={policy},enabled=true")
            logger.debug(f"Converted rule provider: {name} with policy: {policy}")
            
    return result

def convert_config_content(clash_config):
    """Convert clash config content to Loon format"""
    logger.info("Starting config conversion")
    loon_config = []
    
    # Convert proxies
    if 'proxies' in clash_config:
        logger.debug("Converting proxies section")
        loon_config.append('[Proxy]')
        for proxy in clash_config['proxies']:
            converted = convert_proxy(proxy)
            if converted:
                loon_config.append(converted)
                
    # Convert proxy providers
    if 'proxy-providers' in clash_config:
        logger.debug("Converting proxy providers section")
        loon_config.append('\n[Remote Proxy]')
        providers = convert_proxy_providers(clash_config['proxy-providers'])
        loon_config.extend(providers)
                
    # Convert proxy groups
    if 'proxy-groups' in clash_config:
        logger.debug("Converting proxy groups section")
        loon_config.append('\n[Proxy Group]')
        groups = convert_proxy_groups(clash_config['proxy-groups'],
                                   clash_config.get('proxies', []))
        loon_config.extend(groups)
        
    # Convert rule providers
    if 'rule-providers' in clash_config:
        logger.debug("Converting rule providers section")
        loon_config.append('\n[Remote Rule]')
        providers = convert_rule_providers(clash_config['rule-providers'], clash_config.get('rules', []))
        loon_config.extend(providers)
        
    # Convert rules
    if 'rules' in clash_config:
        logger.debug("Converting rules section")
        loon_config.append('\n[Rule]')
        rules = convert_rules(clash_config['rules'])
        loon_config.extend(rules)
        
    logger.info("Config conversion completed")
    return '\n'.join(loon_config)

@app.route('/')
def serve_config():
    try:
        # Get config URL from query parameters
        config_url = request.args.get('url')
        logger.info(f"Received request with config URL: {config_url}")
        
        if config_url:
            # Download config from URL
            logger.debug(f"Downloading config from URL: {config_url}")
            response = requests.get(config_url)
            response.encoding = 'utf-8'  # Ensure proper encoding for Chinese characters
            clash_config = yaml.safe_load(response.text)
        else:
            # Read clash config from local file
            logger.debug(f"Reading config from local file: {config_file}")
            with open(config_file, 'r', encoding='utf-8') as f:
                clash_config = yaml.safe_load(f)
            
        output_content = convert_config_content(clash_config)
        logger.info("Config conversion successful")
            
        # Return as text file
        return Response(output_content,
                       mimetype='text/plain',
                       headers={'Content-Disposition': 'attachment;filename=loon.conf'})
                       
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return str(e), 500

if __name__ == '__main__':
    if len(sys.argv) == 2:
        config_file = sys.argv[1]
        if not os.path.exists(config_file):
            logger.error(f"Error: File {config_file} does not exist")
            sys.exit(1)
        logger.info(f"Using config file: {config_file}")
        
    # Start web server
    logger.info("Starting web server on 0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)