# wireshark
## Utilisation
### Compilation
Il suffit de compiler le fichier Wireshark.java:
```
javac Wireshark.java
```
### Exécution
Le programme prend en argument le fichier pcap à parser:
```
java Wireshark file.pcap
```
## Exemple
Voici un exemple avec le dernier paquet du fichier arp.pcap:
![image](https://github.com/Tr0llope/wireshark/assets/91729752/b59da8b2-81a7-4ff1-aac5-6a808a8caeb2)

Le même paquet vu avec wireshark:
![image](https://github.com/Tr0llope/wireshark/assets/91729752/825e90be-78b2-481d-9842-680ea5bf193f)


## Démarche
Ce projet fonctionne de la manière suivante:  
Il prend un fichier pcap en argument et va le parcourir byte par byte.
On lit d'abord les 16 octets de l'en tête global puis on récupère la taille des paquets.
A chaque paquet, le programme décode des informations qui lui permet de savoir quels sont les protocoles présents.  
Le parcours du fichier se fait dans PcapReader.java. 
Le fichier Interpreter.java contient les fonctions qui interpretent les bytes pour retourner une information compréhensible pour l'utilisateur.
Le fichier Parser.java contient les différentes configurations de lecture en fonction du protocole lu.

### Améliorations
La fonction de suivi du flux TCP n'est pas implémentée.
La fragmentation n'est pas non plus supportée.


