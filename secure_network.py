'''
Program Name: secure_network
Author: Jaroslav
Date: 27.08.2023
Description:
   This program analyzes the private network and evaluates whether the MAC address of the router or other devices
    in the network has changed. If there are two or more identical IP addresses in the network with the same MAC 
    address, the user is notified with the option to terminate data transfer to and from the network. 
    The program runs both in Windows and in Linux

'''
import os
import sys
import platform  # Umožňuje zisťovať informácie o operačnom systéme.
import subprocess  # Umožňuje spúšťať systémové príkazy.
import json  # Umožňuje manipuláciu s JSON dátami.
import time  # Poskytuje metódy týkajúce sa času, napr. pauzovanie.
import tkinter as tk  # Základný modul grafickej knižnice pre vytváranie GUI.
from tkinter import messagebox  # Modul pre zobrazovanie správ.
import socket # Nový import pre prácu so systémovými informáciami

EXEMPTED_IPS = {"10.0.2.255", "255.255.255.255"}  # Zoznam IP adries, ktoré chceme vynimnúť z kontroly
EXEMPTED_MACS = {"ff-ff-ff-ff-ff-ff"}  # Príklad MAC adries


# Definujeme funkciu na zistenie typu operačného systému.
def detect_os():
    ''' Funkcia `detect_os()` slúži na rozpoznanie a určenie typu operačného systému, na ktorom je kód spustený.

1. Funkcia začína volaním funkcie `platform.system()`, ktorá vráti názov aktuálneho operačného systému, napríklad "Windows", "Linux" alebo "Darwin".

2. Potom na základe získaného názvu operačného systému funkcia určí:

   - Ak je názov "Windows", funkcia vráti hodnotu "windows", čo znamená, že operačný systém je Windows.
   - Ak je názov "Linux", funkcia potom overí, či je to v skutočnosti Android (ktorý je postavený na Linuxe). Robí to tak, že kontroluje názov verzie OS (platform.release()) a hľadá v ňom reťazec "android". Ak nájde reťazec "android", vráti hodnotu "android", v opačnom prípade vráti hodnotu "linux".
   - Ak je názov "Darwin", funkcia vráti hodnotu "apple", pretože MacOS je postavený na Darwin jadre.

3. V prípade, že názov operačného systému sa nezhoduje s žiadnym z vyššie uvedených názvov, funkcia vráti hodnotu "unknown", čo znamená, že operačný systém je neznámy alebo nie je v tomto kóde explicitne rozpoznaný.

V skratke, táto funkcia detekuje a rozlíši medzi bežnými operačnými systémami, ako sú Windows, Linux, Android a MacOS, a v prípade, že nenájde známy operačný systém, vráti hodnotu "unknown". '''

    system = platform.system()  # Získanie názvu operačného systému.
    if system == "Windows":
        return "windows"  # Vraciame, že operačný systém je Windows.
    elif system == "Linux":
        # Kontrolujeme či je systém Android (ktorý je postavený na Linuxe).
        if "android" in platform.release().lower():
            return "android"  # Vraciame, že operačný systém je Android.
        else:
            return "linux"  # Vraciame, že operačný systém je Linux.
    elif system == "Darwin":  # MacOS je postavený na Darwin jadre.
        return "apple"  # Vraciame, že operačný systém je MacOS.
    else:
        return "unknown"  # Vraciame, že operačný systém je neznámy.


# Voláme funkciu detect_os() a ukladáme jej výstup do premennej os_type.
os_type = detect_os()


def get_default_gateway():
    """Funkcia `get_default_gateway()` slúži na získanie IP adresy predvoleného routera (tzn. predvolenej brány) v sieti.
     Je navrhnutá tak, aby fungovala v operačných systémoch Linux aj Windows.

1. **Vnútorná funkcia `is_valid_ip(ip_str)`:**
    - Táto funkcia skontroluje, či je zadaný reťazec platnou IPv4 adresou. Získava reťazec ako vstup a overuje nasledujúce:
        * Či reťazec obsahuje štyri časti oddelené bodkami.
        * Či každá časť je číslo.
        * Či každá časť je medzi 0 a 255 (výlučne).
    - Funkcia vráti `True`, ak sú všetky podmienky splnené, inak vráti `False`.

2. Na základe operačného systému (`os.name`) funkcia určuje, či sa nachádza na Linuxe alebo na Windowse.

3. **Pre Linux:**
    - Pomocou príkazu `ip route` funkcia získa informácie o smerovaní v sieti. Hľadá riadok s označením "default",
    ktorý obsahuje informácie o predvolenej bráne, a vráti tretiu položku z tohto riadka, ktorá by mala byť IP adresou
    predvoleného routera.

4. **Pre Windows:**
    - Pomocou príkazu `ipconfig` funkcia získa sieťové informácie o počítači. Prehľadáva výstup a hľadá riadok
    začínajúci "Default Gateway". Po nájdení tohto riadka funkcia prekontroluje, či posledná položka v riadku je platná
    IP adresa (s využitím vyššie definovanej funkcie `is_valid_ip`). Ak je platná, vráti ju.

5. Ak funkcia nenašla žiadnu IP adresu pre predvolenú bránu alebo sa vyskytol nejaký problém, vráti hodnotu `None`.

Celkovo táto funkcia slúži na získanie IP adresy predvoleného routera v sieti v závislosti od toho, či je spustená
na Linuxe alebo na Windowse."""

    def is_valid_ip(ip_str):
        """Kontroluje, či reťazec je platná IPv4 adresa."""
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        for item in parts:
            if not item.isdigit():
                return False
            if not 0 <= int(item) <= 255:
                return False
        return True

    # Zistite typ operačného systému
    os_type = 'linux' if os.name == 'posix' else 'windows'

    if os_type == 'linux':
        cmd = ['ip', 'route']
        result = subprocess.run(cmd, stdout=subprocess.PIPE)
        for line in result.stdout.decode('utf-8', errors='replace').split('\n'):
            if 'default' in line:
                return line.split()[2]

    elif os_type == 'windows':
        cmd = ['ipconfig']
        result = subprocess.run(cmd, stdout=subprocess.PIPE)
        lines = result.stdout.decode('cp1252', errors='replace').split('\n')
        for i, line in enumerate(lines):
            if "Default Gateway" in line:
                potential_ip = line.split()[-1]
                if is_valid_ip(potential_ip):  # Kontrolujte platné IP adresy
                    return potential_ip

    return None


def get_current_network_info():
    """Táto funkcia, `get_current_network_info()`, je navrhnutá tak, aby získala tri kľúčové informácie o aktuálnej
    sieti, ktorá je pripojená k zariadeniu:

1. **SSID (názov siete):** Unikátny identifikátor, ktorý rozlišuje bezdrôtové siete.

2. **MAC adresa routera:** Fyzická adresa routera v sieti.

3. **IP adresa routera (predvolená brána):** IP adresa, na ktorú sú smerované všetky pakety, ktoré nie sú určené pre
zariadenia v lokálnej sieti.

Podrobne:

- Začne inicializáciou `ssid` na `None`. Toto zabezpečuje, že máme prednastavenú hodnotu, ak by sme z nejakého dôvodu
nedokázali získať aktuálne SSID.

- Ak je aktuálny operačný systém Windows (`os_type` je nastavený na `'windows'`):
    - Používa príkaz `netsh wlan show interfaces` na získanie informácií o aktuálne pripojených bezdrôtových sieťach.
    - Prechádza každý riadok výstupu tohto príkazu a hľadá riadok, ktorý obsahuje "SSID", ale nie "BSSID". Ak nájde taký
     riadok, získa SSID (názov siete) tým, že rozdelí tento riadok na dve časti podľa dvojbodky (`:`) a vezme druhú časť.

- Ak nie je operačný systém Windows (predpokladá sa, že je to Linux):
    - Používa príkaz `iwgetid -r` na získanie aktuálneho SSID.
    - Dekóduje výstup tohto príkazu a odstraňuje prázdne miesta na začiatku a konci, čím získa SSID.

- Na získanie MAC adresy routera:
    - Používa funkciu `get_default_gateway()` na získanie IP adresy predvolenej brány (toto je zvyčajne IP adresa vášho
     domáceho routera).
    - Následne získava ARP tabuľku pomocou funkcie `get_arp_table()`.
    - Pokúša sa nájsť MAC adresu routera v ARP tabuľke podľa získanej IP adresy predvolenej brány.

Na záver funkcia vráti získané SSID, MAC adresu routera a IP adresu routera (predvolenú bránu) ako trojicu hodnôt."""

    ssid = None  # Inicializuje premennú 'ssid' s hodnotou None.

    if os_type == 'windows':  # Kontroluje, či je aktuálny operačný systém Windows.
        cmd = ['netsh', 'wlan', 'show', 'interfaces']  # Nastavuje príkaz pre získanie informácií o sieti na Windows.
        result = subprocess.run(cmd, stdout=subprocess.PIPE)  # Spustí príkaz a uchováva jeho výstup.

        # Prechádza každý riadok výstupu príkazu.
        for line in result.stdout.decode('utf-8').split('\n'):

            if 'SSID' in line and not 'BSSID' in line:  # Kontroluje, či riadok obsahuje SSID, ale nie BSSID.
                ssid = line.split(':')[1].strip()  # Extrakcia SSID z riadku a odstránenie prázdnych miest z okrajov.

    else:  # Ak nie je operačný systém Windows (predpokladá sa Linux).
        cmd = ['iwgetid', '-r']  # Nastavuje príkaz pre získanie SSID na Linux.
        result = subprocess.run(cmd, stdout=subprocess.PIPE)  # Spustí príkaz a uchováva jeho výstup.
        ssid = result.stdout.decode('utf-8').strip()  # Dekóduje výstup a odstraňuje prázdne miesta z okrajov, aby získala SSID.

    # Získaj MAC adresu routera
    default_gateway = get_default_gateway()  # Získava predvolenú bránu (IP adresu).
    arp_table = get_arp_table()  # Získava ARP tabuľku.
    router_mac = arp_table.get(default_gateway, None)  # Získava MAC adresu routera podľa IP adresy predvolenej brány.

    return ssid, router_mac, default_gateway   # Vracia SSID a MAC adresu routera a IP routra.


def save_attack_history(ip, old_mac, new_mac, user_ignored=False, attack_end=False, filename="attack_history.json"):
    ''' Táto funkcia, `save_attack_history()`, slúži na ukladanie histórie útokov založených na
    ARP (Address Resolution Protocol) do súboru vo formáte JSON. Funkcia je špecifikovaná pre detekciu a evidenciu
    útokov typu ARP spoofing alebo podobných, kde môže dôjsť k zmene MAC adresy priradenej k IP adrese.

Funkcia má nasledujúce vstupné parametre:
- **ip:** IP adresa, ktorá bola napadnutá.
- **old_mac:** Pôvodná MAC adresa priradená k danej IP adrese.
- **new_mac:** Nová (potenciálne útočnícka) MAC adresa, ktorá bola priradená tej istej IP adrese.
- **user_ignored (voliteľný):** Flag, ktorý indikuje, či užívateľ ignoroval detekciu útoku.
- **attack_end (voliteľný):** Flag, ktorý indikuje, či bol útok ukončený.
- **filename (voliteľný):** Názov súboru, do ktorého sa ukladá história útokov. Predvolená hodnota je "attack_history.json".

Priebeh funkcie:
1. **Načítanie existujúcej histórie útokov:** Funkcia skúsi otvoriť súbor s názvom špecifikovaným v parametri `filename`
 a načíta z neho históriu útokov. Ak súbor neexistuje alebo obsahuje chybné dáta, inicializuje sa prázdny zoznam
  `attack_history`.

2. **Získanie aktuálnej ARP tabuľky:** Funkcia získava aktuálnu ARP tabuľku pomocou funkcie `get_arp_table()`.

3. **Získanie aktuálneho času:** Aktuálny čas je získaný vo formáte "YYYY-MM-DD HH:MM:SS" v UTC
 (koordinovaný svetový čas) pomocou modulu `time`.

4. **Vytvorenie nového záznamu:** Vytvára sa nový záznam o útoku (slovník v Pythone) s detailami útoku ako je čas,
 IP adresa, stará a nová MAC adresa, informácie o tom, či užívateľ ignoroval útok, či bol útok ukončený a aktuálna ARP tabuľka.

5. **Pridanie záznamu do histórie:** Nový záznam je pridaný do zoznamu `attack_history`.

6. **Ukladanie histórie útokov:** Celý zoznam `attack_history` je uložený späť do súboru s názvom špecifikovaným
v parametri `filename` vo formáte JSON s odsadením 4 medzery pre lepšiu čitateľnosť.

Celkovo táto funkcia slúži na evidenciu potenciálnych útokov v sieti založených na zmenách v ARP tabuľke, čo je častá
 technika používaná útočníkmi pri MITM (Man-in-the-Middle) útokoch. '''

    try:
        with open(filename, "r") as file:
            attack_history = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        attack_history = []

    current_arp_table = get_arp_table()  # Získanie aktuálnej ARP tabuľky

    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    entry = {
        "time": current_time,
        "ip": ip,
        "old_mac": old_mac,
        "new_mac": new_mac,
        "user_ignored": user_ignored,
        "attack_end": attack_end,  # Pridanie informácie o ukončení útoku
        "arp_table": current_arp_table   # Ukladáme aktuálnu ARP tabuľku spolu so záznamom o útoku

    }
    attack_history.append(entry)

    with open(filename, "w") as file:
        json.dump(attack_history, file, indent=4)


# Funkcia na ukladanie histórie pripojení
def save_connection_history(successful, ssid, ip, mac, attack_detected=False, filename="connection_history.json"):

    ''' Táto funkcia, `save_connection_history()`, slúži na ukladanie histórie pripojení do súboru vo formáte JSON.
     Funkcia zaznamenáva informácie o pripojení, ako je úspešnosť pripojenia, názov siete (SSID), IP adresa,
      MAC adresa a či bol detekovaný nejaký útok.

Funkcia má nasledujúce vstupné parametre:
- **successful:** Boolovská hodnota, ktorá indikuje, či bolo pripojenie úspešné.
- **ssid:** Názov siete (SSID), ku ktorej sa zariadenie snažilo alebo úspešne pripojilo.
- **ip:** IP adresa zariadenia.
- **mac:** MAC adresa zariadenia.
- **attack_detected (voliteľný):** Boolovská hodnota, ktorá indikuje, či bol počas pripojenia detekovaný nejaký útok.
- **filename (voliteľný):** Názov súboru, do ktorého sa ukladá história pripojení.
 Predvolená hodnota je "connection_history.json".

Priebeh funkcie:
1. **Načítanie existujúcej histórie pripojení:** Funkcia sa pokúsi otvoriť súbor s názvom špecifikovaným v parametri
`filename` a načíta z neho históriu pripojení. Ak súbor neexistuje alebo obsahuje chybné dáta,
inicializuje sa prázdny zoznam `history`.

2. **Získanie aktuálneho času:** Aktuálny čas je získaný vo formáte "YYYY-MM-DD HH:MM:SS" v UTC
(koordinovaný svetový čas) pomocou modulu `time`.

3. **Vytvorenie nového záznamu:** Vytvára sa nový záznam o pripojení (slovník v Pythone) s detailami,
ako sú čas pripojenia, úspešnosť pripojenia, názov siete, IP a MAC adresa zariadenia a informácia o tom,
či bol detekovaný nejaký útok.

4. **Pridanie záznamu do histórie:** Nový záznam je pridaný do zoznamu `history`.

5. **Ukladanie histórie pripojení:** Celý zoznam `history` je uložený späť do súboru s názvom špecifikovaným v parametri
 `filename` vo formáte JSON s odsadením 4 medzery pre lepšiu čitateľnosť.

Celkovo táto funkcia slúži na evidenciu pripojení, čo môže byť užitočné pre analýzu sieťových pripojení a detekciu
potenciálnych útokov alebo problémov s pripojením. '''

    try:
        with open(filename, "r") as file:
            history = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        history = []

    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())  # Získanie aktuálneho času
    entry = {"time": current_time, "successful": successful, "ssid": ssid, "ip": ip, "mac": mac, "attack_detected": attack_detected}
    history.append(entry)

    with open(filename, "w") as file:
        json.dump(history, file, indent=4)  # 4 medzery pre odsadenie každého záznamu


def save_arp_table(arp_table, filename='arp_table.json'):
    '''Táto funkcia, `save_arp_table()`, ukladá ARP (Address Resolution Protocol) tabuľku do súboru vo formáte JSON.

Funkcia má nasledujúce vstupné parametre:
- **arp_table:** ARP tabuľka, ktorá sa má uložiť. Táto tabuľka je zvyčajne reprezentovaná ako slovník, kde kľúče sú IP
 adresy a hodnoty sú príslušné MAC adresy.
- **filename (voliteľný):** Názov súboru, do ktorého sa má ARP tabuľka uložiť. Predvolená hodnota je "arp_table.json".

Priebeh funkcie:
1. **Otvorenie súboru:** Funkcia otvorí súbor so špecifikovaným názvom v režime zápisu (`'w'` znamená, že obsah súboru
bude prepísaný, ak súbor už existuje).
2. **Ukladanie ARP tabuľky:** Pomocou funkcie `json.dump()` z modulu `json` sa ARP tabuľka uloží do súboru vo formáte
JSON. Parametre `file` a `indent=4` určujú, kam sa dáta majú uložiť a ako budú odsadené
(4 medzery pre lepšiu čitateľnosť).

Celkovo táto funkcia slúži na ukladanie ARP tabuľky do súboru, čo môže byť užitočné pre analýzu alebo monitorovanie
zmeny v ARP tabuľke. Ukladanie ARP tabuľky môže napomôcť pri detekcii ARP spoofing útokov alebo iných
 sieťových nezrovnalostí.'''

    with open(filename, 'w') as file:  # Otvoríme súbor na zápis.
        json.dump(arp_table, file, indent=4)  # 4 medzery pre odsadenie každého záznamu a Zapíšeme ARP tabuľku do súboru.


# Definujeme funkciu, ktorá načíta ARP tabuľku zo súboru vo formáte JSON.
def load_arp_table(filename='arp_table.json'):
    ''' Táto funkcia, `load_arp_table()`, slúži na načítanie ARP (Address Resolution Protocol) tabuľky zo súboru
     vo formáte JSON.

Funkcia má nasledovujúce vstupné parametre:
- **filename (voliteľný):** Názov súboru, z ktorého sa má ARP tabuľka načítať. Predvolená hodnota je "arp_table.json".

Priebeh funkcie:
1. **Otvorenie súboru:** Funkcia otvorí súbor so špecifikovaným názvom v režime čítania (`'r'` znamená, že súbor je
 otvorený v režime čítania).
2. **Načítanie ARP tabuľky:** Pomocou funkcie `json.load()` z modulu `json` sa ARP tabuľka načíta zo súboru vo formáte
JSON. Po načítaní je ARP tabuľka okamžite vrátená ako výstup z funkcie.

Zhrnutie: Funkcia `load_arp_table()` slúži na načítanie ARP tabuľky zo súboru vo formáte JSON. Môže byť použitá na
 získanie uloženej ARP tabuľky pre porovnanie alebo ďalšiu analýzu. '''

    with open(filename, 'r') as file:  # Otvoríme súbor na čítanie.
        return json.load(file)  # Načítame a vrátime ARP tabuľku zo súboru.


def check_connection_change():
    ''' Funkcia `check_connection_change()` overuje, či došlo k zmene v pripojení na základe histórie pripojení a
    aktuálnych sieťových informácií.

Podrobnejší opis:

1. **Načítanie histórie pripojení:** Funkcia sa pokúsi načítať históriu pripojení zo súboru `connection_history.json`.
Pokiaľ sa úspešne načíta história, bude posledné pripojenie priradené premennej `last_connection`.

2. **Chybová obsluha:** Ak súbor s históriou neexistuje alebo nastane iná chyba pri načítavaní (napríklad je prázdny
alebo obsahuje nesprávny formát dát), funkcia vráti hodnotu `False` (t.j. považuje sa, že nedošlo k žiadnej zmene).

3. **Získanie aktuálnych sieťových informácií:** Pomocou funkcie `get_current_network_info()` sú získané aktuálne
 sieťové informácie: SSID siete, MAC adresa routera a IP adresa zariadenia.

4. **Porovnanie histórie s aktuálnymi informáciami:** Funkcia porovnáva históriu pripojení s aktuálnymi sieťovými
 informáciami a rozhoduje na základe nasledujúcich prípadov:
    - **Prípad 1:** Ak sa zmenila len MAC adresa, ale SSID zostalo rovnaké, funkcia vráti `True`.
    - **Prípad 2:** Ak sa zmenila MAC adresa a zároveň aj SSID, funkcia vráti `False`.
    - **Prípad 3:** Ak sa zmenilo len SSID, MAC adresa zostala rovnaká, ale zmenila sa IP adresa, funkcia vráti `True`.
    - **Prípad 4:** Ak sa zmenilo SSID, zároveň sa zmenila MAC adresa a IP adresa, funkcia vráti `False`.

5. **Výstup:** Ak aktuálne informácie o pripojení nevyhovujú žiadnemu z vyššie uvedených prípadov, funkcia vráti `False`.

V skratke, táto funkcia overuje, či došlo k zmene v sieťovom pripojení na základe porovnania histórie pripojení s
aktuálnymi sieťovými informáciami a reaguje na špecifikované scenáre zmien. '''

    try:
        # Načítanie histórie pripojení
        with open("connection_history.json", "r") as file:
            history = json.load(file)
            last_connection = history[-1]
    except:
        # Ak história neexistuje alebo je prázdna, vrátime False (žiadna zmena)
        return False

    ssid, router_mac, ip = get_current_network_info()

    # Prípad 1: Ak sa zmenila MAC adresa, ale SSID zostalo rovnaké
    if last_connection['mac'] != router_mac and last_connection['ssid'] == ssid:
        return True

    # Prípad 2: Ak sa zmenila MAC adresa a zároveň aj SSID
    if last_connection['mac'] != router_mac and last_connection['ssid'] != ssid:
        return False

    # Prípad 3: Ak sa zmenilo SSID, MAC adresa zostala rovnaká, ale zmenila sa IP adresa
    if last_connection['ssid'] != ssid and last_connection['mac'] == router_mac and last_connection['ip'] != ip:
        return True

    # Prípad 4: Ak sa zmenilo SSID, zároveň sa zmenila MAC adresa a zmenilo sa IP adresa
    if last_connection['ssid'] != ssid and last_connection['mac'] != router_mac and last_connection['ip'] != ip:
        return False

    return False  # Ak nevyhovuje žiadnemu z vyššie uvedených prípadov, vrátime False


# Definujeme funkciu, ktorá odpojí zariadenie z siete.
def disconnect_from_network():
    ''' Funkcia `disconnect_from_network()` má za úlohu odpojiť zariadenie od siete. Ako odpojenie sa vykoná
    závisí na type operačného systému zariadenia.

    Podrobnejší opis:

    1. **Linux:**
        - Ak je zariadenie s operačným systémom Linux, funkcia použije nástroj `nmcli` (ktorý je súčasťou väčšiny
         distribúcií Linuxu) na odpojenie siete.
        - Konkrétne príkaz: `nmcli device disconnect wlan0` odpojí zariadenie od siete cez rozhranie `wlan0`,
         ktoré je často predvolené názvoslovné označenie pre bezdrôtové rozhranie na Linuxe.

    2. **Windows:**
        - Ak je zariadenie s operačným systémom Windows, funkcia použije príkazový riadok `netsh` na deaktiváciu a následnú
        reaktiváciu bezdrôtového rozhrania (Wi-Fi).
        - Prvý príkaz: `netsh interface set interface Wi-Fi admin=disable` deaktivuje Wi-Fi rozhranie.
        - Druhý príkaz: `netsh interface set interface Wi-Fi admin=enable` následne reaktivuje Wi-Fi rozhranie.

    Výsledkom je, že zariadenie bude odpojené od aktuálnej siete. Funkcia dokáže pracovať s dvoma najrozšírenejšími
    operačnými systémami - Linuxom a Windows. Ak operačný systém zariadenia nie je ani
    Linux ani Windows, funkcia neurobí nič. '''

    if os_type == "linux":
        subprocess.run(["nmcli", "device", "disconnect", "wlan0"])
    elif os_type == "windows":
        subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=disable"])
        subprocess.run(["netsh", "interface", "set", "interface", "Wi-Fi", "admin=enable"])


# Funkcia zobrazí dialógové okno s výstrahou o zmene MAC adresy.
def user_decision_dialog(ip, old_mac, new_mac):
    ''' Funkcia `user_decision_dialog()` má za úlohu zobraziť užívateľovi dialógové okno s upozornením na zmenu
    MAC adresy. Ak užívateľ stlačí tlačidlo "Áno", funkcia vráti hodnotu `True`, ak tlačidlo "Nie", vráti `False`.

    Podrobnejší opis:

    1. **Príprava GUI okna:**
        - `root = tk.Tk()`: Toto je spôsob, ako vytvoriť nové GUI okno v knižnici Tkinter.
        - `root.withdraw()`: Hneď ako vytvoríme hlavné okno, chceme ho skryť, pretože potrebujeme iba dialógové okno,
         nie celé GUI.

    2. **Nastavenie dialógového okna:**
        - `root.attributes('-topmost', True)`: Týmto príkazom sa nastaví, aby sa dialógové okno zobrazilo v popredí
        všetkých ostatných okien.

    3. **Príprava a zobrazenie správy:**
        - Funkcia prijíma tri argumenty - `ip`, `old_mac` a `new_mac`.
        - Tieto hodnoty sú použité na vytvorenie správy upozornenia, ktorá informuje užívateľa o zmene MAC adresy.
        - `msg = f"ALERT: MAC adresa pre IP {ip} sa zmenila z {old_mac} na {new_mac}.\n\nPokračovať v komunikácii?"`:
         Toto je formátovaná správa, ktorá obsahuje informácie o IP adrese a starú a novú MAC adresu.
        - `response = messagebox.askyesno("ARP Alert", msg)`: Zobrazí sa dialógové okno s titulkom "ARP Alert" a vyššie
         uvedenou správou. Toto dialógové okno ponúka užívateľovi dve možnosti: "Áno" a "Nie".

    4. **Ukončenie a vrátenie hodnoty:**
        - `root.destroy()`: Po tom, čo užívateľ odpovie, hlavné GUI okno (`root`) je zatvorené/likvidované.
        - `return response`: Funkcia vráti hodnotu, ktorá je `True`, ak užívateľ stlačil "Áno" alebo `False`,
         ak stlačil "Nie".

    Táto funkcia môže byť užitočná v prípade, ak chcete upozorniť užívateľa na možnú hrozbu v sieti alebo na neočakávanú
    zmenu v sieťových nastaveniach a získať rozhodnutie od užívateľa, či chce pokračovať v komunikácii alebo nie. '''

    root = tk.Tk()  # Vytvoríme hlavné okno GUI.
    root.withdraw()  # Skryjeme hlavné okno.

    # Uistíme sa, že dialógové okno sa zobrazí v popredí.
    root.attributes('-topmost', True)

    # Vytvoríme správu pre dialógové okno.
    msg = f"ALERT: MAC adresa pre IP {ip} sa zmenila z {old_mac} na {new_mac}.\n\nPokračovať v komunikácii?"
    response = messagebox.askyesno("ARP Alert", msg)  # Zobrazíme dialógové okno a získame odpoveď užívateľa.

    root.destroy()  # Zatvoríme hlavné okno GUI.
    return response  # Vrátime odpoveď užívateľa.


def has_inconsistent_mac(current_arp_table, original_arp_table):
    """Funkcia `has_inconsistent_mac()` skontroluje, či sú v aktuálnej ARP tabuľke (`current_arp_table`)
    nejaké nezrovnalosti v MAC adresách v porovnaní s pôvodnou ARP tabuľkou (`original_arp_table`).
    Funkcia vráti `True`, ak nájde aspoň jednu nesúladnú MAC adresu; v opačnom prípade vráti `False`.

    Podrobnejšie:

    1. Funkcia prijíma dve ARP tabuľky ako vstup: aktuálnu ARP tabuľku a pôvodnú (alebo referenčnú) ARP tabuľku.

    2. Funkcia prechádza všetkými záznamami (IP adresami a príslušnými MAC adresami) v aktuálnej
    ARP tabuľke pomocou cyklu `for`.

    3. Pre každý záznam (IP a MAC) v aktuálnej ARP tabuľke kontroluje:
       - Či táto IP adresa existuje aj v pôvodnej ARP tabuľke.
       - Či MAC adresa pre túto IP v aktuálnej ARP tabuľke sa zhoduje s MAC adresou pre rovnakú IP v pôvodnej ARP tabuľke.

    4. Ak sa nájde nejaká nesúladnosť (tj. MAC adresa pre konkrétnu IP v aktuálnej tabuľke sa nelíši od tej v
    pôvodnej tabuľke), funkcia vráti hodnotu `True`.

    5. Ak prechádza všetkými záznamami v aktuálnej ARP tabuľke a nenašla žiadne nezrovnalosti, vráti hodnotu `False`.

    Vo výsledku táto funkcia poskytuje jednoduchý mechanizmus na kontrolu, či sa v sieti neobjavila nejaká neočakávaná
    zmena MAC adresy, čo môže byť znakom potenciálnej hrozby alebo útoku, napr. ARP spoofingu."""

    for ip, mac in current_arp_table.items():
        if ip in original_arp_table and original_arp_table[ip] != mac:
            return True
    return False


def get_arp_table():
    ''' Funkcia `get_arp_table()` slúži na získanie ARP (Address Resolution Protocol) tabuľky z operačného systému.
     Výstupom tejto funkcie je slovník (`arp_dict`), kde kľúčom je IP adresa a hodnotou je MAC adresa. Prístup na
     získanie tejto tabuľky sa líši v závislosti od operačného systému, a preto funkcia obsahuje vetvenie pre
     Linux a Windows.

    Podrobne:

    1. Vytvára sa prázdny slovník `arp_dict`, ktorý bude obsahovať IP adresy ako kľúče a MAC adresy ako hodnoty.

    2. Ak je aktuálny operačný systém typu Linux:
       - Použije sa príkaz `arp -n` na získanie ARP tabuľky.
       - Dekóduje sa výstup príkazu do reťazca s použitím kódovania 'utf-8'.
       - Rozdelí sa dekódovaný výstup na riadky a vylučuje sa prvý riadok (hlavička tabuľky).
       - Pre každý riadok sa kontroluje jeho stĺpce. Ak sú stĺpce platné, extrahuje sa z nich IP adresa a MAC adresa,
       ktoré sa pridajú do slovníka `arp_dict`.

    3. Ak je aktuálny operačný systém typu Windows:
       - Použije sa príkaz `arp -a` na získanie ARP tabuľky.
       - Dekóduje sa výstup príkazu do reťazca s použitím kódovania 'cp1252'.
       - Rozdelí sa dekódovaný výstup na riadky a vylučujú sa prvé tri riadky (hlavička tabuľky a prázdne riadky).
       - Pre každý riadok sa kontroluje jeho stĺpce. Ak sú stĺpce platné a IP adresa nekončí dvojbodkou (čo znamená,
       že to nie je hlavička sekcie), extrahuje sa z nich IP adresa a MAC adresa, ktoré sa pridajú do slovníka `arp_dict`.

    4. Na konci sa funkcia vráti so slovníkom `arp_dict`, ktorý obsahuje ARP tabuľku.

    Táto funkcia poskytuje jednoduchý spôsob, ako získať ARP tabuľku z rôznych operačných systémov, čo môže byť užitočné
    napríklad pri monitorovaní zmeny MAC adries v sieti alebo pri detekcii ARP spoofingu. '''

    arp_dict = {}
    if os_type == 'linux':
        cmd = ['arp', '-n']
        result = subprocess.run(cmd, stdout=subprocess.PIPE)
        lines = result.stdout.decode('utf-8', errors='replace').split('\n')[1:]
        for line in lines:
            columns = line.split()
            if len(columns) >= 3:
                ip = columns[0]
                mac = columns[2]
                arp_dict[ip] = mac
    elif os_type == 'windows':
        cmd = ['arp', '-a']
        result = subprocess.run(cmd, stdout=subprocess.PIPE)
        lines = result.stdout.decode('cp1252', errors='replace').split('\n')[3:]
        for line in lines:
            columns = line.split()
            if len(columns) >= 2:
                ip = columns[0]
                if not ip.endswith(":"):  # Vylučujeme hlavičky, ktoré končia dvojbodkou
                    mac = columns[1]
                    arp_dict[ip] = mac

    #print(arp_dict)
    return arp_dict


def duplicate_mac_dialog(mac, ips):
    ''' Funkcia `duplicate_mac_dialog` je dizajnovaná tak, aby informovala užívateľa o detekcii duplicitnej
    MAC adresy v ARP tabuľke a poskytovala možnosti reakcie na túto situáciu.

    Podrobne:

    1. **Nastavenie titulku a správy dialógového okna:**
       - Funkcia prijíma dva parametre: `mac` (duplicitná MAC adresa) a `ips` (zoznam IP adries, ktoré používajú
       túto duplicitnú MAC adresu).
       - Titulok dialógového okna je nastavený na "ARP Duplicitná MAC Alert".
       - Zoznam IP adries je transformovaný na reťazec s IP adresami oddelenými čiarkami.
       - Správa dialógového okna je vytvorená s využitím f-stringu tak, aby informovala užívateľa o detekovanej duplicitnej
        MAC adrese a príslušných IP adresách, a ponúkla možnosti reakcie.

    2. **Vytvorenie a zobrazenie dialógového okna:**
       - Inicializuje sa hlavné okno GUI prostredníctvom `tk.Tk()`.
       - Hlavné okno GUI je následne skryté použitím `withdraw()`.
       - S využitím `attributes('-topmost', True)`, je zabezpečené, že dialógové okno sa zobrazí v popredí všetkých
        ostatných okien.
       - Metóda `messagebox.askyesnocancel()` sa používa na zobrazenie dialógového okna s troma tlačidlami:
        Yes, No a Cancel. Odpoveď užívateľa je uložená v premennej `response`.
       - Hlavné okno GUI je potom zatvorené.

    3. **Interpretácia odpovede užívateľa a návrat hodnoty:**
       - Ak užívateľ klikne na "Cancel", funkcia vráti hodnotu `"ban"`.
       - Ak užívateľ klikne na "Yes", funkcia vráti hodnotu `"ignore"`.
       - Ak užívateľ klikne na "No", funkcia vráti hodnotu `"disconnect"`.

    Hodnoty návratu ("ban", "ignore", "disconnect") sú navrhnuté tak, aby umožnili volajúcej funkcii rozhodnúť o
     ďalšom kroku v reakcii na detekciu duplicitnej MAC adresy. '''

    title = "ARP Duplicitná MAC Alert"
    ip_list = ", ".join(ips)
    msg = f"ALERT: Duplicitná MAC adresa {mac} detekovaná pre IP adresy: {ip_list}.\n\nAkceptovať hrozbu, odpojiť sa alebo zakázať komunikáciu s týmito IP adresami?"

    root = tk.Tk()  # Vytvoríme hlavné okno GUI.
    root.withdraw()  # Skryjeme hlavné okno.
    root.attributes('-topmost', True)
    response = messagebox.askyesnocancel(title, msg)  # AskYesNoCancel vráti True (Yes), False (No) alebo None (Cancel)
    root.destroy()

    if response is None:  # Cancel
        return "ban"
    elif response:  # Yes
        return "ignore"
    else:  # No
        return "disconnect"


# Funkcia na získanie zoznamu IP adries s rovnakou MAC adresou
def get_ips_with_mac(arp_table, mac):
    ''' Táto funkcia `get_ips_with_mac` je určená na získanie zoznamu IP adries, ktoré v ARP tabuľke majú
    priradenú konkrétnu MAC adresu.

    Podrobne:

    1. **Vstupné parametre:**
       - `arp_table`: Slovník reprezentujúci ARP tabuľku, kde kľúče sú IP adresy a hodnoty sú MAC adresy.
       - `mac`: MAC adresa, pre ktorú chceme zistiť zoznam priradených IP adries.

    2. **Telo funkcie a výpočet:**
       - Používa sa zoznamová komprehenzia, ktorá prechádza cez všetky položky (IP a MAC pary) v ARP tabuľke
       (`arp_table.items()`).
       - Pre každý pár (IP, MAC) v tabuľke funkcia skontroluje, či aktuálna MAC adresa (`current_mac`)
       sa zhoduje s hľadanou MAC adresou (`mac`).
       - Ak sa MAC adresy zhodujú, príslušná IP adresa je pridaná do výstupného zoznamu.

    3. **Výstup:**
       - Funkcia vráti zoznam IP adries, ktoré majú v ARP tabuľke priradenú hľadanú MAC adresu.

    Napríklad, ak by sme mali ARP tabuľku reprezentovanú slovníkom:
    `{'192.168.1.1': '00:11:22:33:44:55', '192.168.1.2': '00:11:22:33:44:55', '192.168.1.3': '66:77:88:99:AA:BB'}`
    a zavolali funkciu `get_ips_with_mac` s MAC adresou `'00:11:22:33:44:55'`, funkcia by vrátila zoznam:
    `['192.168.1.1', '192.168.1.2']`. '''
    return [ip for ip, current_mac in arp_table.items() if current_mac == mac]


def has_duplicate_mac(arp_table):
    """
    Funkcia `has_duplicate_mac` slúži na kontrolu ARP tabuľky s cieľom zistiť, či obsahuje duplicitné MAC adresy.
    Ak nájde v ARP tabuľke duplicitné MAC adresy, vráti zoznam týchto MAC adries.

    Podrobne:

    1. **Vstupný parameter:**
       - `arp_table`: Slovník reprezentujúci ARP tabuľku, kde kľúče sú IP adresy a hodnoty sú MAC adresy.

    2. **Telo funkcie a výpočet:**
       - `mac_counts`: Slovník na uchovávanie počtu výskytov jednotlivých MAC adries v ARP tabuľke.
       Kľúč je MAC adresa a hodnota je počet jej výskytov.
       - `duplicates`: Zoznam, ktorý bude obsahovať duplicitné MAC adresy nájdené v ARP tabuľke.
       - Prechádzame cez všetky IP a MAC páry v ARP tabuľke. Pre každú MAC adresu inkrementujeme jej počet
        výskytov v slovníku `mac_counts`.
       - Ak aktuálna MAC adresa má vo slovníku `mac_counts` hodnotu väčšiu ako 1 (čiže sa vyskytuje viackrát
        v ARP tabuľke), NEpatrí do výnimiek `EXEMPTED_MACS` a príslušná IP adresa NEpatrí do výnimiek
         `EXEMPTED_IPS`, pridáme túto MAC adresu do zoznamu `duplicates`.
       - Nakoniec vraciame unikátny zoznam (získaný cez konverziu do množiny a naspäť do zoznamu) MAC adries,
        ktoré boli identifikované ako duplicitné.

    3. **Výstup:**
       - Funkcia vráti zoznam duplicitných MAC adries z ARP tabuľky (ak sú nejaké). Ak v ARP tabuľke nie sú
        žiadne duplicitné MAC adresy, vráti prázdny zoznam.

    Poznámka:
    - Funkcia očakáva, že existujú premenné (pravdepodobne globálne) `EXEMPTED_MACS` a `EXEMPTED_IPS`, ktoré
    obsahujú MAC adresy alebo IP adresy, ktoré by mali byť ignorované pri hľadaní duplicitných MAC adries.
        """
    mac_counts = {}
    duplicates = []

    for ip, mac in arp_table.items():
        mac_counts[mac] = mac_counts.get(mac, 0) + 1
        if mac_counts[mac] > 1 and mac not in EXEMPTED_MACS and ip not in EXEMPTED_IPS:
            duplicates.append(mac)

    return list(set(duplicates))


def alert_admin(ip, old_mac, new_mac):
    """Funkcia `alert_admin` upozorní správcu alebo užívateľa na zmenu MAC adresy v ARP tabuľke a podľa
    rozhodnutia užívateľa vykoná príslušné akcie.

    Podrobne:

    1. **Vstupné parametre:**
       - `ip`: IP adresa zariadenia, ktorého MAC adresa sa zmenila.
       - `old_mac`: Pôvodná MAC adresa.
       - `new_mac`: Nová MAC adresa.

    2. **Telo funkcie a výpočet:**
       - Najprv sa užívateľovi zobrazí dialógové okno pomocou funkcie `user_decision_dialog`,
       ktoré upozorní na zmenu MAC adresy a žiada ho o rozhodnutie, či chce pokračovať v komunikácii.
       - Na základe rozhodnutia užívateľa sa informácie o útoku uložia do súboru `attack_history.json`
        prostredníctvom funkcie `save_attack_history`.
       - Ak užívateľ rozhodol, že nechce pokračovať v komunikácii (`user_decision` je `False`):
         - Vypíše sa varovná správa s informáciami o zmenenej MAC adrese.
         - Získajú sa informácie o aktuálnej sieti prostredníctvom `get_current_network_info`.
         - Uložia sa informácie o neúspešnom pripojení (útok bol detekovaný) do `connection_history.json`.
         - Zariadenie sa odpojí od siete pomocou funkcie `disconnect_from_network`.
         - Vypíše sa informačná správa o automatickom odpojení.
         - Funkcia vráti hodnotu `False`.
       - Ak užívateľ rozhodol pokračovať v komunikácii:
         - Získajú sa informácie o aktuálnej sieti.
         - Uložia sa informácie o úspešnom pripojení do `connection_history.json`.
         - Funkcia vráti hodnotu `True`.

    3. **Výstup:**
       - Funkcia vráti `True`, ak užívateľ rozhodol pokračovať v komunikácii, inak vráti `False`.

    V podstate, funkcia umožňuje užívateľovi rozhodnúť sa, či chce pokračovať v komunikácii v prípade
    zmeny MAC adresy a podniká príslušné akcie na základe tohto rozhodnutia."""

    user_decision = user_decision_dialog(ip, old_mac, new_mac)

    # Uložíme informácie o útoku do attack_history.json
    save_attack_history(ip, old_mac, new_mac, user_decision)

    if not user_decision:
        print(f"ALERT: MAC adresa pre IP {ip} sa zmenila z {old_mac} na {new_mac}.")
        ssid, router_mac, ip = get_current_network_info()

        save_connection_history(successful=False, ssid=ssid, ip=ip, mac=new_mac, attack_detected=True)
        disconnect_from_network()
        print("Systém automaticky zrušil pripojenie do siete kvôli možnému ARP spoof útoku.\n")
        return False
    else:
        ssid, router_mac, ip = get_current_network_info()

        save_connection_history(successful=True, ssid=ssid, ip=ip, mac=new_mac)
        return True


def monitor_arp_changes(interval=10, alert_func=None):
    """Funkcia `monitor_arp_changes` sleduje zmeny v ARP tabuľke v stanovených intervaloch a pri detekcii
     nezrovnalostí alebo duplicitných MAC adries upozorňuje užívateľa a podniká príslušné akcie.

    Podrobne:

    1. **Vstupné parametre:**
       - `interval`: Časový interval v sekundách, v ktorom sa ARP tabuľka kontroluje.
       - `alert_func`: Funkcia, ktorá sa môže volať pri detekcii zmeny (nie je v kóde explicitne použitá).

    2. **Telo funkcie a výpočet:**
       - Získame predvolenú bránu (gateway) aktuálnej siete.
       - Pokúšame sa načítať pôvodnú ARP tabuľku. Ak sa to nepodarí (napr. ak tabuľka ešte nebola vytvorená),
       aktuálnu ARP tabuľku uložíme ako pôvodnú.
       - Získame informácie o aktuálnej sieti a uložíme ich do histórie pripojení.
       - Kontrolujeme zmenu pripojenia; ak je detegovaná zmena, užívateľa sa pýta, či chce pokračovať.
        V prípade nesúhlasu sa zariadenie odpojí od siete a monitorovanie sa ukončí.

       - Vo večnom cykle (`while True`):
         - Získame aktuálnu ARP tabuľku.
         - Kontrolujeme prítomnosť duplicitných MAC adries.
           - Ak sú zistené, užívateľa sa pýta na ďalšie kroky pre každú duplicitnú MAC adresu.
           - Na základe rozhodnutia užívateľa sa môže zariadenie odpojiť od siete alebo pridať problémové
            IP adresy do zoznamu zakázaných adries.
         - Ak neexistujú duplicitné MAC adresy, ale existujú nesrovnalosti v ARP tabuľke, aktualizuje sa
          pôvodná ARP tabuľka s novými hodnotami.

         - Po každej kontrole čakáme na ďalší interval (pomocou `time.sleep(interval)`) pred opätovným
          skenovaním ARP tabuľky.

    3. **Výstup:**
       - Funkcia neposkytuje priamy výstup (vrátenú hodnotu), namiesto toho vykonáva rôzne akcie na základe
        zmeny v ARP tabuľke (ako je odpojenie od siete alebo aktualizácia ARP tabuľky).

    Zhrnutie: Funkcia neustále monitoruje ARP tabuľku a pri detekcii podozrivých aktivít
    (duplicitné MAC adresy alebo zmena MAC adresy pre známu IP adresu) upozorňuje užívateľa a podniká príslušné akcie.
    """

    default_gateway = get_default_gateway()
    try:  # Skúste načítať pôvodnú ARP tabuľku
        original_arp_table = load_arp_table()

    except:  # V prípade výnimky (napr. ak tabuľka neexistuje) získame aktuálnu ARP tabuľku a uložíme ju
        original_arp_table = get_arp_table()
        save_arp_table(original_arp_table)

    ssid, router_mac, ip = get_current_network_info()  # Získame aktuálne informácie o sieti (SSID a MAC adresu routera)
    save_connection_history(successful=True, ssid=ssid, ip=default_gateway, mac=router_mac)  # Uložíme históriu pripojenia s aktuálnymi informáciami o sieti

    if check_connection_change():  # Kontrola zmeny pripojenia na začiatku monitorovania
        user_decision = user_decision_dialog("Connection Alert", "Detekovaná zmena pripojenia! Chcete pokračovať?") # Vytvoríme dialógové okno pre užívateľa, ktorý upozorňuje na zmenu pripojenia
        if not user_decision:
            print("Zmena pripojenia bola zaznamenaná")  # V prípade, že užívateľ odmietne pripojenie, vypíše sa správa
            # save_connection_history(get_current_network_info() + (False,))
            save_connection_history(successful=False, ssid=ssid, ip=default_gateway, mac=router_mac)
            disconnect_from_network()
            return
        else:
            save_connection_history(successful=True, ssid=ssid, ip=default_gateway, mac=router_mac)
            # save_connection_history(get_current_network_info() + (True,))  # V prípade súhlasu užívateľa sa uložia informácie o novom pripojení

    while True:
        current_arp_table = get_arp_table()
        duplicate_macs = has_duplicate_mac(current_arp_table)

        # Kontrolujeme duplicitné MAC adresy
        if duplicate_macs:
            for mac in duplicate_macs:
                ips_with_same_mac = get_ips_with_mac(current_arp_table, mac)
                decision = duplicate_mac_dialog(mac, ips_with_same_mac)

                if decision == "disconnect":
                    disconnect_from_network()
                    return
                elif decision == "ban":
                    # Pridajte všetky problematické IP adresy do zoznamu zakázaných adries
                    for ip in ips_with_same_mac:
                        EXEMPTED_IPS.add(ip)
            save_arp_table(current_arp_table)
            time.sleep(interval)
        elif has_inconsistent_mac(current_arp_table, original_arp_table):  # Ak je v ARP tabuľke nesúlad
            for ip, mac in current_arp_table.items():
                if ip not in EXEMPTED_IPS and ip in original_arp_table and original_arp_table[ip] != mac:
                    # Uložíme informácie o ukončení útoku
                    save_attack_history(ip, original_arp_table[ip], mac, user_ignored=True, attack_end=True)
                    original_arp_table[ip] = mac  # Aktualizujeme pôvodnú ARP tabuľku
            save_arp_table(current_arp_table)
        time.sleep(interval)


# Ak je tento skript spustený, ako hlavný program, spustíme monitorovanie ARP tabuľky.
def main():
    try:
        monitor_arp_changes(alert_func=alert_admin)
    except KeyboardInterrupt:
        print("\nMonitorovanie ARP tabuľky bolo prerušené.")


if __name__ == "__main__":
    main()

arp_table = load_arp_table()
duplicates = has_duplicate_mac(arp_table)
print("Duplicitné MAC adresy:", duplicates)

