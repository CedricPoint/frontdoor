# frontdoor

[English](README.md) · **Français**

**La porte d'entrée de votre site est-elle fermée à clé ?** Une commande la
regarde comme le ferait un navigateur — TLS, redirections, en-têtes de
sécurité, attributs de cookies —, note ce qu'elle trouve, et affiche les lignes
nginx, Caddy ou Apache qui corrigent ce qui manque.

[![CI](https://github.com/CedricPoint/frontdoor/actions/workflows/ci.yml/badge.svg)](https://github.com/CedricPoint/frontdoor/actions/workflows/ci.yml)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](package.json)
[![dépendances](https://img.shields.io/badge/d%C3%A9pendances-0-brightgreen.svg)](package.json)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

```console
$ npx github:CedricPoint/frontdoor github.com

  frontdoor  github.com                                    A  91/100

  tls       50 days left · Sectigo Limited · TLSv1.3
  http      goes to https, in one hop
  page      HTTP 200 · 80 ms

  ▲  Content-Security-Policy — present, but allows 'unsafe-inline'
     Those put back most of what the policy was meant to take away.
     nginx  add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;

  ▲  Permissions-Policy — missing
     Embedded third-party code can ask for the camera, the microphone or the location on your behalf.
     nginx  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

  ✔  12 passed   The site answers over HTTPS, http:// goes to https://, The certificate is trusted +9 more
  –  1 skipped   TLS 1.0 and 1.1 are refused (this Node build cannot speak TLS 1.0/1.1)
```

*(L'outil s'exprime en anglais : sa sortie se colle dans un ticket, un journal
de CI ou une discussion avec un hébergeur, où le reste l'est déjà.)*

Chaque constat vient avec la raison pour laquelle il compte — en une phrase, pas
en numéro de CVE — et la ligne qui le referme.

## Le morceau qu'on veut vraiment

```bash
frontdoor example.com --fix nginx
```

```nginx
# frontdoor — example.com, nginx

# one year, subdomains included
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
# widen this one directive at a time, starting from the console errors
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# http:// goes to https://
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

`--fix caddy` et `--fix apache` écrivent la même chose dans leur syntaxe. La
politique proposée est un point de départ pour un site ordinaire : si vous
intégrez des éléments tiers, il faudra l'élargir, une directive à la fois, la
console du navigateur ouverte.

## Ce qu'il vérifie

| | |
| --- | --- |
| **TLS** | le site répond en HTTPS · le certificat est reconnu, porte exactement ce nom, et n'est pas sur le point d'expirer · TLS 1.2 ou 1.3 est utilisé · TLS 1.0 et 1.1 sont refusés |
| **Redirections** | `http://` arrive bien sur `https://`, en combien de sauts, et sans jamais redescendre en `http://` |
| **En-têtes** | `Strict-Transport-Security` (lu, pas seulement compté) · `Content-Security-Policy` (et s'il autorise `unsafe-inline`) · `X-Content-Type-Options` · la mise en cadre, via `X-Frame-Options` ou `frame-ancestors` · `Referrer-Policy` · `Permissions-Policy` |
| **Cookies** | `Secure`, `HttpOnly` et `SameSite`, cookie par cookie, par nom |
| **Hygiène** | un en-tête `Server:` qui donne sa version, `X-Powered-By`, et l'existence de `/.well-known/security.txt` |

Seize contrôles, pondérés. Un contrôle auquel on ne peut pas répondre
honnêtement est ignoré plutôt que deviné : ce qui n'est pas testable ne coûte
jamais de points. Un certificat cassé plafonne la note quoi qu'il arrive, parce
qu'un navigateur s'arrête là lui aussi.

## En CI, ou dans une tâche planifiée

```bash
frontdoor example.com --min-grade B     # sortie 1 en dessous de cette note
frontdoor a.com b.com c.com             # l'un après l'autre, puis un récapitulatif
frontdoor example.com --json            # le rapport complet, en-têtes compris
```

| sortie | signification |
| --- | --- |
| `0` | vérifié, et au-dessus de `--min-grade` si vous en avez demandé une |
| `1` | en dessous de la note demandée |
| `2` | rien n'a répondu, ou invocation incorrecte |

Le contrôle d'expiration du certificat est celui qui mérite une tâche
hebdomadaire : il avertit à 21 jours et échoue à 7, ce qui laisse le temps de
s'apercevoir que le renouvellement automatique a cessé de fonctionner en
silence.

## Ce qu'il ne fait pas

C'est une revue de configuration, pas un test d'intrusion, et la différence est
voulue :

- Il demande la page d'accueil, `/.well-known/security.txt`, et fait une ou deux
  poignées de main TLS. C'est ce que fait un navigateur à chaque visite.
- **Aucune charge utile, aucun essai de chemins, aucune tentative de passer
  outre quoi que ce soit.** Il lit ce que le serveur donne à tout visiteur, et
  rien d'autre.
- **La valeur des cookies n'est jamais lue.** Seulement leur nom et leurs
  attributs, pour que la sortie puisse être collée dans un ticket sans risque.
- Il ne dit rien de votre application. Une note parfaite ici et une injection SQL
  sur le formulaire de connexion sont parfaitement compatibles.

## Installation

```bash
npx github:CedricPoint/frontdoor example.com      # rien d'installé
npm install -g github:CedricPoint/frontdoor
```

Node 18 ou plus récent. Aucune dépendance, aucune étape de construction, aucun
fichier de configuration.

## Comme bibliothèque

```js
import { probe, analyse } from 'frontdoor';

const report = analyse(await probe('example.com'));

if (report.grade === 'F') process.exitCode = 1;
for (const result of report.results.filter((r) => r.status === 'fail')) {
  console.log(result.title, '—', result.detail);
}
```

`probe()` ne fait qu'observer et `analyse()` ne fait que juger : c'est ce qui
rend tout le catalogue de contrôles testable sans réseau.

## Tests

50. Chaque contrôle est exercé contre des observations fabriquées — un
certificat expiré, un joker qui ne couvre pas le nom demandé, une redirection
qui retombe en http, un cookie sans `Secure` — et la couche réseau tourne contre
un vrai serveur HTTP local : chaînes de redirections, boucles, redirections
relatives, ports fermés, délais dépassés.

```bash
npm test
```

## Licence

MIT
