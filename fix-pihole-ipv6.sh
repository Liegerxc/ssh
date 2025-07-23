#!/bin/bash

# Verificar se é root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script deve ser executado como root. Use 'sudo -i' e execute novamente."
    exit 1
fi

echo "==============================================="
echo "  CORREÇÃO PARA PI-HOLE COM PROBLEMAS DE IPv6  "
echo "==============================================="

## 1. Desativar IPv6 no sistema
echo -e "\n[1/5] Desativando IPv6 no sistema..."
grep -q "disable_ipv6" /etc/sysctl.conf || cat >> /etc/sysctl.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

sysctl -p

## 2. Configurar Pi-hole para usar apenas IPv4
echo -e "\n[2/5] Configurando Pi-hole para IPv4 apenas..."
pihole -a -i local

# Configurar DNS explícitos IPv4
sed -i '/^PIHOLE_DNS_/d' /etc/pihole/setupVars.conf
cat >> /etc/pihole/setupVars.conf <<EOF
PIHOLE_DNS_1=1.1.1.1
PIHOLE_DNS_2=1.0.0.1
IPV6_ADDRESS="none"
EOF

## 3. Ajustar configuração do WireGuard
echo -e "\n[3/5] Ajustando WireGuard..."
if [ -f /etc/wireguard/wg0.conf ]; then
    # Adicionar comandos para desativar IPv6 se não existirem
    if ! grep -q "disable_ipv6" /etc/wireguard/wg0.conf; then
        sed -i '/\[Interface\]/a PostUp = sysctl -w net.ipv6.conf.all.disable_ipv6=1; sysctl -w net.ipv6.conf.default.disable_ipv6=1' /etc/wireguard/wg0.conf
    fi
    
    # Garantir que o DNS do Pi-hole está configurado
    if [ -f /etc/wireguard/client.conf ]; then
        sed -i 's/DNS = .*/DNS = 10.8.0.1/' /etc/wireguard/client.conf
    fi
fi

## 4. Configurar firewall
echo -e "\n[4/5] Configurando firewall..."
ufw allow 53/udp comment "Pi-hole DNS"
ufw allow 51820/udp comment "WireGuard"

# Limpar regras IPv6
ip6tables -F
ip6tables -X
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

## 5. Reiniciar serviços
echo -e "\n[5/5] Reiniciando serviços..."
systemctl restart pihole-FTL
systemctl restart wg-quick@wg0 >/dev/null 2>&1
systemctl restart systemd-resolved

echo -e "\n==============================================="
echo "  CORREÇÕES APLICADAS COM SUCESSO!"
echo "==============================================="
echo -e "\nVerificações finais:\n"

# Testar conectividade
echo -n "Teste de DNS (IPv4): "
dig +short google.com @1.1.1.1 || echo "ERRO"

echo -n "Status do Pi-hole: "
pihole status | grep -i "DNS service"

if [ -f /etc/wireguard/client.conf ]; then
    echo -e "\nConfiguração do cliente WireGuard:"
    echo "Arquivo: /etc/wireguard/client.conf"
    qrencode -t ansiutf8 < /etc/wireguard/client.conf 2>/dev/null || echo "Instale 'qrencode' para ver o QR Code"
fi

echo -e "\nRecomendações finais:"
echo "1. Reconecte seus dispositivos à VPN WireGuard"
echo "2. Verifique as configurações de DNS nos seus clientes"
echo "3. Monitore os logs com: pihole tail"
