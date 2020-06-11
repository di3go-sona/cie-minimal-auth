## Cie Minimal Authentication

Questo software é stato realizzato come parte del programma di ricerca del [Dipartimento di Ingegneria dell’Informazione, Elettronica e Telecomunicazioni](https://web.uniroma1.it/dip_diet/en) sugli alcuni aspetti di sicurezza della nuova Carta di identitá elettronica ( CIE ).

#### Obiettivo

L'obiettivo principale della ricerca é quello di creare un protocollo di sicurezza minimale per applicazioni non critiche come, ad esempio, un sistema di gestione dei titoli di trasporto nei mezzi pubblici.

#### Protocollo

L'idea é di implementare un protocollo di challenge response monodirezionale, in cui  l'utente si autenticherá con il lettore. 

````scala
+------------------------------------------------------------------+
|                                                                  |
|    +--------------+ 1                       +---------------+    |
|    |              |    Agree on k_pub       |               |    |
|    |              <------------------------->               |    |
|    |              |                         |               |    |
|    |              | 2                       |               |    |
|    |              |          Nonce          |               |    |
|    |              +------------------------->               |    |
|    |              |                         |  CARTA        |    |
|    |   LETTORE    |     ENC(Nonce,k_pub)    |  IDENTITA     |    |
|    |              <-------------------------+  ELETTRONICA  |    |
|    |              |                         |               |    |
|    |              |                         |               |    |
|    |              | N  := Nonce             |               |    |
|    |              | S  := ENC(N,k_pub)      |               |    |
|    |              | R  := DEC(S,k_pub)      |               |    |
|    |              | if N==R  then -> ok     |               |    |
|    +--------------+          else -> ko     +---------------+    |
|                                                                  |
+------------------------------------------------------------------+
````



A tal proposito sono previste due primitive:

1. **Registrazione carta** ( Passive Authentication )

2. **Validazione carta** ( Active Authentication)

Al fine di poter effettuare la validazione attraverso il meccanismo di challenge response, il lettore della carta NFC dovrà prima controllare che la coppia ( ID, Chiave Pubblica ) sia valida. A tal fine sono previste le seguenti operazioni di **lettura**:

- Lettura Chiave Pubblica (EF.SERVIZI_KPUB)
- Lettura Certificato Utente (EF.SOD)
- Lettura Hash Firmato della Chiave pubblica con il Certificato dell'Utente (EF.SOD)

Addizionalmente viene letto anche il NIS (Numero Identificativo Servizi) posto a lettura libera nella CIE per queste situazioni, infatti essi non rilascia alcuna informazione personale, tuttavia in caso di necessitá alcuni organi di competenza son ( o saranno ) dotati di un applicativo per risalire risalire all'identitá dellutente dietro all'identificativo in questione.

- Lettura Numero identificativo dei servizi (NIS) (EF.NIS)

Il file EF.SOD contiente un PKCS#7 signed data, ovvero un messagio firmato, 



#### Repository

Questa repository contiene un codice per poter
