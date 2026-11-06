# vlanmesh

Matrice de connectivité inter-VLAN pour valider des règles de pare-feu.

Un LXC Proxmox avec une patte par VLAN teste **toutes** les paires
(source VLAN i → cible VLAN j) en ICMP, force le trafic à travers le firewall,
et publie le résultat dans un dashboard + `/metrics` Prometheus.

```
┌──────────────── LXC vlanmesh (Docker host-net) ────────────────┐
│ eth0 mgmt        UI web /metrics / SSH                         │
│ eth1 vlan10  192.168.10.5/24 ┐                                 │
│ eth2 vlan20  192.168.20.5/24 ├ une table de routage par VLAN    │
│ ...                          ┘                                 │
│   prober Go  →  SQLite  →  matrice + /metrics                  │
└──────────────┬─────────────────────────────────────────────────┘
               │ src 192.168.i.5 → dst 192.168.j.254
               │ sortie forcée par eth_i (policy routing)
        ┌──────▼───────┐
        │ OPNsense     │  .254 de chaque VLAN
        └──────────────┘
```

## Ce que ça teste vraiment

Chaque cellule `i → j` envoie des pings depuis l'IP du LXC sur le VLAN i vers
la cible du VLAN j (par défaut `.254`, donc OPNsense). Le paquet sort
physiquement par `eth_i`, entre dans OPNsense par l'interface VLAN i, et la
règle d'entrée de cette interface décide.

- `REJECTED` : ICMP type 3 code 9/10/13 → règle OPNsense en **reject**.
- `BLOCKED` : timeout → règle **block/drop**.
- `OK` / `DEGRADED` : joignable (perte éventuelle).
- `UNKNOWN` : la sonde de contrôle `i → i` a échoué → le VLAN source est HS,
  on ne conclut pas sur les règles.
- `UNEXPECTED_ALLOW` : joignable alors que `policy.yaml` dit deny (trou de sécu).
- `UNEXPECTED_DENY` : bloqué alors que `policy.yaml` dit allow (cassé).
- **Colonne Internet** : ping vers `1.1.1.1` / `8.8.8.8` depuis chaque VLAN, en
  sortant par sa passerelle. `internet: deny` sur un VLAN (caméras, IoT…)
  doit donner `BLOCKED` ; si ça répond, c'est `UNEXPECTED_ALLOW`.

> **Limite v1** : viser `.254` teste la règle d'entrée d'OPNsense, pas un vrai
> flux forwardé vers un hôte, et pas les ports. Pour valider un vrai
> `host → host` et du TCP/UDP, passer `targets.mode: hosts` avec un hôte par
> VLAN (voir plus bas).

## Démarrage rapide (démo, sans réseau)

```bash
go run . -config config.demo.yaml
# http://localhost:8080
```

Résultats simulés, mais l'UI, l'historique, la politique et `/metrics` sont
réels.

## Pourquoi le policy routing est obligatoire

Le LXC a une IP dans chaque VLAN. Sans rien faire, le kernel voit tous les
subnets en direct : un ping vers `192.168.20.254` sortirait par `eth2` et
**contournerait OPNsense**. Le prober :

1. ouvre un socket ICMP brut lié à l'IP source,
2. applique `SO_BINDTODEVICE eth_i`,
3. s'appuie sur une table de routage par VLAN (`ip rule` + `ip route`).

L'app pose elle-même ces règles au démarrage (idempotent) :

```
ip route replace 192.168.10.0/24 dev eth1 src 192.168.10.5 table 100
ip route replace default via 192.168.10.254 dev eth1 table 100
ip rule add from 192.168.10.5 lookup 100 pref 1000
```

`rp_filter` doit être en mode **loose** (`2`) : la réponse revient par `eth_i`
alors que sa route inverse est sur un autre VLAN. En strict (`1`), tout est
droppé.

## Installation sur Proxmox

### 1. Créer le LXC

Debian 12/13, privilégié ou non. Dans les options :

```
features: nesting=1,keyctl=1
```

Unprivileged fonctionne, mais Docker + overlay2 échoue souvent (overlay sur
overlay). Si besoin :

```bash
cat >/etc/docker/daemon.json <<'EOF'
{ "storage-driver": "vfs" }
EOF
systemctl restart docker
```

### 2. Interfaces

Une patte par VLAN. Exemple `/etc/pve/lxc/<id>.conf` :

```
net0: name=eth0,bridge=vmbr0,tag=99,ip=192.168.99.5/24,gw=192.168.99.254,hwaddr=AA:BB:CC:00:00:01
net1: name=eth1,bridge=vmbr0,tag=10,ip=192.168.10.5/24,hwaddr=AA:BB:CC:00:00:02
net2: name=eth2,bridge=vmbr0,tag=20,ip=192.168.20.5/24,hwaddr=AA:BB:CC:00:00:03
...
```

- **`gw=` uniquement sur `net0`** (management). Pas de passerelle par défaut
  sur les pattes data : c'est l'app qui gère le routage par VLAN.
- Chaque patte doit être en **/24** (ou le masque réel du VLAN), jamais en /16,
  sinon les routes se chevauchent.
- `tag=` = le VLAN de la patte.

### 3. `rp_filter`

Dans le LXC :

```bash
cat >/etc/sysctl.d/99-vlanmesh.conf <<'EOF'
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.eth1.rp_filter=2
net.ipv4.conf.eth2.rp_filter=2
# ... une ligne par patte
EOF
sysctl --system
```

L'app vérifie ce réglage et l'affiche dans le bandeau « points à corriger » si
ce n'est pas bon.

### 4. Docker

```bash
apt install docker.io docker-compose-plugin   # ou get.docker.com
git clone <repo> vlanmesh && cd vlanmesh
cp config.yaml config.yaml.local   # adapter les VLANs
docker compose up -d --build
```

Le conteneur tourne en `network_mode: host` avec `NET_ADMIN` + `NET_RAW` :
c'est indispensable pour voir les pattes du LXC et écrire les règles de
routage dans le netns du LXC.

### 5. OPNsense

- Une interface par VLAN, IP `.254`.
- Règles sur l'interface d'entrée (comportement pf standard).
- Les règles `block` donnent `BLOCKED`, les `reject` donnent `REJECTED`.

## Configuration

Voir `config.yaml`. Points clés :

```yaml
interval: 30s
count: 3
timeout: 1s
concurrency: 8
db: /data/vlanmesh.db
retention: 720h
demo: false

vlans:
  - {name: vlan10, vlan_id: 10, iface: eth1, src: 192.168.10.5/24, gateway: 192.168.10.254}

targets:
  mode: gateway        # gateway | hosts
  hosts: {}            # hosts: {vlan10: 192.168.10.10, ...}

internet:
  enabled: true
  targets: ["1.1.1.1", "8.8.8.8"]
  default: allow       # attente par défaut, "allow", "deny" ou ""
  # par VLAN, dans la liste vlans :
  #   - {..., internet: deny}

policy:
  default: allow
  rules:
    - {from: vlan10, to: vlan20, action: deny}

alerts:
  webhook: ""          # POST JSON à chaque changement d'état
```

`policy` accepte `*` des deux côtés :

```yaml
rules:
  - {from: vlan10, to: "*", action: deny}
```

## Cibles hôtes (recommandé pour du vrai forward)

Déjà supporté par le code, à activer dès que tu as un hôte par VLAN :

```yaml
targets:
  mode: hosts
  hosts:
    vlan10: 192.168.10.10
    vlan20: 192.168.20.10
```

Chaque hôte doit répondre à l'ICMP et être distinct du LXC. Le LXC ne peut pas
être sa propre cible : le kernel livre en local avant de router, donc la voie
retour serait court-circuitée.

## Accès Internet par VLAN

Pour vérifier qu'un VLAN est bien coupé d'Internet (caméras, IoT, invités…) :

```yaml
internet:
  enabled: true
  targets: ["1.1.1.1", "8.8.8.8"]
  default: allow

vlans:
  - {name: vlan10, ..., internet: allow}
  - {name: cameras, ..., internet: deny}
```

- Chaque VLAN ping les cibles **en sortant par sa propre passerelle** (donc via
  OPNsense et le WAN).
- Joignable si **au moins une** cible répond → `OK` ; aucune → `BLOCKED`
  (`REJECTED` si ICMP admin prohibited).
- `deny` + joignable → `UNEXPECTED_ALLOW` (le blocage Internet ne marche pas).
- `allow` + bloqué → `UNEXPECTED_DENY` (cassé).
- L'historique est disponible sur la cellule `vlan → internet`.

Limite : c'est un test ICMP. Si ta règle bloque seulement le TCP/443 mais
laisse passer l'ICMP, le dashboard dira `OK` à juste titre. Pour tester un port
précis, il faudra un test TCP (pas encore implémenté).

## CLI

```bash
vlanmesh -config config.yaml -check   # valide config + réseau, n'écrit rien
vlanmesh -config config.yaml -once    # un sweep, matrice texte, exit
vlanmesh -config config.demo.yaml     # dashboard en mode démo
vlanmesh -version
```

`-once` est la commande de validation P0 :

```
$ vlanmesh -config config.yaml -once
src \ dst   vlan10        vlan20        vlan30
vlan10      ctl OK        BLOCKED       OK 0.62ms
vlan20      REJECT        ctl OK        OK 0.55ms
vlan30      OK 0.71ms     OK 0.58ms     ctl OK
sweep #1  2026-11-06T18:50:15Z  9 cells  0 violation(s)
```

## Procédure de validation (P0)

1. Depuis le LXC : `ping -I eth1 192.168.20.254` doit répondre.
2. Sur OPNsense, `tcpdump -ni <iface_vlan10> icmp` : la requête doit entrer par
   **VLAN10** (pas VLAN20). Si elle entre par VLAN20, le policy routing ne
   s'applique pas.
3. Ajouter une règle temporaire `block ICMP VLAN10 → VLAN20`.
4. `vlanmesh -once` : la cellule `vlan10 → vlan20` passe `BLOCKED` (ou
   `REJECTED` si règle reject).
5. Supprimer la règle : la cellule repasse `OK`.

## Dashboard

- Matrice : ligne = source, colonne = destination. Survol = détail, clic =
  historique + latence + verdict de politique.
- Bandeau haut : compteurs, dernier sweep, mode démo/live.
- Bandeau orange : problèmes réseau détectés (interface absente, IP manquante,
  `rp_filter=1`, ...).
- `═` rouge pointillé autour d'une cellule = écart entre la politique déclarée
  et le mesuré.
- `/metrics` : séries Prometheus, prêtes pour Grafana.

## Métriques

```
vlanmesh_probe_success{src,dst}              0/1   (dst="internet" pour le WAN)
vlanmesh_internet_success{src}               0/1
vlanmesh_probe_loss_ratio{src,dst}           0..1
vlanmesh_probe_rtt_ms{src,dst,stat}          stat=min|avg|max
vlanmesh_probe_status{src,dst,status}        1 pour le statut courant
vlanmesh_policy_violation{src,dst,type}      1 si écart
vlanmesh_last_sweep_timestamp_seconds
vlanmesh_sweep_duration_seconds
vlanmesh_sweeps_total
vlanmesh_cells_total
```

## Alertes

`alerts.webhook` reçoit un POST JSON à chaque changement d'état :

```json
{
  "type": "state_change",
  "at": "2026-11-06T18:50:15Z",
  "message": "vlanmesh: connectivity state changed",
  "cells": [
    {"src":"vlan10","dst":"vlan20","status":"timeout","expected":"allow",
     "violation":"unexpected_deny","loss":1,"src_ip":"192.168.10.5",
     "dst_ip":"192.168.20.254"}
  ]
}
```

Compatible ntfy, Gotify, Discord (via un petit adaptateur), ou un webhook
maison.

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `need CAP_NET_RAW` | `cap_add: NET_RAW` manquant |
| `check policy routing` | `ip rule`/`ip route` absents, ou IP source absente de l'iface |
| Toutes les cellules `UNKNOWN` | sonde de contrôle `i→i` KO : mauvaise IP/passerelle/interface |
| `interface ethX not found` | patte absente dans la config Proxmox |
| Tout `BLOCKED` alors que le ping manuel passe | `rp_filter=1`, ou trafic sortant par le mauvais VLAN |
| Docker ne démarre pas | overlay2 sur LXC unprivileged → `storage-driver: vfs` |

## Limites

- IPv4 uniquement.
- Cible `.254` = test d'entrée ICMP, pas de forward réel ni de ports.
- Un LXC ne peut pas être sa propre cible (livraison locale du kernel).
- Le trafic de contrôle (UI, webhook) doit rester hors du firewall testé.
- Ne pas exposer le dashboard publiquement : il a `NET_ADMIN` sur le LXC.
