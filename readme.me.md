wg genkey | tee secrets/server_privatekey | wg pubkey
chmod 600 secrets/server_privatekey
ls -l secrets/server_privatekey

python3 ./wg.py

sudo wg-quick strip ./out/wg1/wg1.conf

sudo wg-quick down /home/joseph/VPS/wg/out/wg1/wg1.conf
sudo wg-quick up /home/joseph/VPS/wg/out/wg1/wg1.conf

## wg0 = test server 
## wg1 = backup server 
## wg2 = media server 

### render configu : 

python3 ./render-wg-conf.py 

### spustenie zaleži od wgx

sudo wg-quick up /home/joseph/VPS/wg/out/wg1/wg1.conf
sudo wg-quick down /home/joseph/VPS/wg/out/wg1/wg1.conf

### PostUp/PostDown vygenerované z renderu
- do požadovaného servera v `wg.yaml` pridaj blok `interface_extras`
- každý riadok sa pridá priamo do `[Interface]`, napr.:

```
interface_extras:
  - PostUp = ip -4 route replace 172.30.0.0/24 dev %i
  - PostDown = ip -4 route del 172.30.0.0/24 dev %i || true
```

- rovnakým spôsobom sa dajú vložiť aj iptables pravidlá pre media server
- ak potrebuješ špeciálne príkazy len pre jedného klienta, pridaj `interface_extras`
  do daného peer záznamu – skončia v `out/<server>/peers/<peer>.conf`

### povolenie uwf

sudo ufw statu 

sudo ufw allow 51821 => pre wg2 akoby 5182x = wgx :D

sudo ufw reload

# čistenie route 

sudo ip -4 route show 172.30.0.0/24
sudo ip -4 route del 172.30.0.0/24 || true
sudo ip -4 route show 172.30.0.0/24

### povolenie forwardingu
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-wg-forward.conf
sudo sysctl --system

## úprava ufw pre forward
sudo nano /etc/default/ufw
DEFAULT_FORWARD_POLICY="ACCEPT"
sudo ufw reload

sudo ufw route allow in on wg2 out on wg2 from 10.2.0.0/24 to 172.30.0.0/24
sudo ufw route allow in on wg2 out on wg2 from 172.30.0.0/24 to 10.2.0.0/24

pravidla pre media server

PostUp = iptables -A FORWARD -i %i -o eth0 -d 172.30.0.0/24 -j ACCEPT; iptables -A FORWARD -i eth0 -o %i -s 172.30.0.0/24 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.2.0.0/24 -d 172.30.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o eth0 -d 172.30.0.0/24 -j ACCEPT; iptables -D FORWARD -i eth0 -o %i -s 172.30.0.0/24 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.2.0.0/24 -d 172.30.0.0/24 -o eth0 -j MASQUERADE

parvidla pre wg2 server

PostUp = ip -4 route replace 172.30.0.0/24 dev %i
PostDown = ip -4 route del 172.30.0.0/24 dev %i || true

sudo nft add table inet wg 2>/dev/null || true
sudo nft 'add chain inet wg forward { type filter hook forward priority 0; policy drop; }' 2>/dev/null || true
sudo nft add rule inet wg forward ct state established,related accept 2>/dev/null || true
sudo nft add rule inet wg forward iifname "wg2" oifname "wg2" accept 2>/dev/null || true
