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

Al fine di poter effettuare la validazione attraverso il meccanismo di challenge response, il lettore della carta NFC dovrà prima controllare che la coppia ( ID, Chiave Pubblica ) sia valida. 
A tal fine, per la **Passive Authentication** sono previste le seguenti operazioni di **lettura**:

- Lettura Chiave Pubblica (EF.SERVIZI_KPUB)
- Lettura Certificato Utente (EF.SOD)
- Lettura degli Hash firmati con Chiave pubblica del Certificato dell'Utente (EF.SOD)
- Lettura Numero identificativo dei servizi (NIS) (EF.NIS)

E le seguenti operazioni di **verifica** :
- Verifica Firma del Certificato Utente ( Verifica certificato x509 con CA del Governo )
- Verifica Firma degli Hash ( verifica di un PKCS#7 Signed Data con Certificato Utente )
- Verifica che gli Hash calcolati a partire da EF.SERVIZI_KPUB e NIS combacino con quelli del punto precende.

Mentre per la **Active Authentication** son previste le seguenti operazioni:
- Lettura (ID, Chiave Pubblica) ovver (EF.NIS, EF.SERVIZI_KPUB)
- Verifica che (ID, Chiave Pubblica) siano presenti nel Database ( ciò indica che hanno superato la passive authentication, senza necessita di rieseguirla )
- Generazione Nonce cauale
- Invio Nonce alla CIE
- Ricezione Firma Nonce
- Verifica Firma Nonce ( Con Chiave Pubblica dei punti precedenti )


#### Repository
Questa repository contiene il codice per poter effettuare tutte le sopra citate operazioni, in particolare si distinguono tre classi:
- Cie: implementa le operazioni di trasmissione/recezioni pacchetti con la carta ( basso livello )
- Cie_Token: implementa le operazioni per effettuare i vari meccanismi di autenticazione 
- Cie_Dumper: implementa alcune utility per estrarre file dalla carta e salvarli localmente

