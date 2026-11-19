# AISafe · harness pentru fișiere codificate

Această variantă rezolvă automat un tip restrâns de problemă. Un fișier din /code trebuie să conțină o valoare completă sau să producă acea valoare după decodare. Suportă hex, Base64 standard cu padding, inversarea octeților și ROT13. Poate rezolva separat proba publică Sanity Check descrisă în kit. Un rezultat cu format valid poate fi un exemplu sau o momeală. Doar gateway-ul confirmă captura.

## Cum rulează

1. Agentul citește timpul și bugetul din /health. Inventariază fișiere obișnuite din volumul read-only, până la 64 de fișiere, 64 KiB pe fișier, 2 MiB în total și 512 intrări. Sare peste linkuri simbolice. Dacă inventarul este incomplet, raportează limita.
2. Încearcă citirea directă și cele patru transformări individuale. Cere ca întregul rezultat, după eliminarea spațiilor marginale, să aibă formatul unui flag. Respinge valorile alcătuite din aceeași cifră hex repetată și cazurile cu mai mulți candidați direcți distincți.
3. Pentru fixture-ul public recunoaște instrucțiunile și prefixul furnizate de organizatori. Citește două resurse statice documentate de pe singura destinație din TARGETS. Nu urmărește redirecturi. Tokenul merge exclusiv la gateway.
4. Pentru un fișier codificat în mai multe straturi poate cere modelului intern un indice de fișier și maximum cinci transformări. Chat Completions permite o cerere simplă cu inventarul, mostre scurte, INSTRUCTIONS și operațiile deja încercate. Agentul validează propunerea și reproduce transformările local. Trimiterea unei valori scrise liber de model este imposibilă prin această interfață.
5. Sunt implicit șase cereri, configurabile prin AGENT_MAX_STEPS până la 14. Fiecare încercare consultă /health. Răspunsul 400 reduce mostra pentru următoarea cerere, 429 și 503 folosesc Retry-After dacă timpul permite, 402 încheie încercările de model, iar 409 oprește bucla. O propunere repetată sau un candidat respins încheie rularea. O eroare de transport la trimitere poate lăsa verdictul necunoscut. Agentul evită retrimiterea automată.

## Rulare de pe calculator

Extrage ZIP-ul și deschide un terminal în directorul care conține compose.yaml. Cu Node instalat, testele rulează fără pachete npm. Testul cu gateway-ul oficial necesită portul local 8080 liber.

```sh
node --test test/harness.test.mjs test/practice.test.mjs
```

Cu Docker Desktop pornit pe Windows, sau Docker Engine și Compose pe Linux, pornește proba locală. Configurația implicită folosește gateway-ul local fără cheie API. Proba publică se rezolvă prin citirea fragmentelor, cu zero cereri către model.

```sh
docker compose up --build --exit-code-from harness
docker compose down -v
```

Așteaptă mesajul „Flag accepted” și codul de ieșire 0. A doua comandă elimină volumele temporare ale acestei probe.

## Construirea imaginii și încărcarea

Windows PowerShell, din același director:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Linux sau macOS:

```sh
sh build.sh
```

Scripturile construiesc pentru linux/amd64 și produc my-harness.tar. Pe platformă, secțiunea Harnesses primește fișierul TAR. Încărcarea înlocuiește harness-ul live al echipei. Verifică întâi rezultatul local și dimensiunea TAR (maximum 1 GiB), apoi rulează Sanity Check pe platformă.

## Verificări și limite

Testele acoperă validarea, decodarea, autentificarea, păstrarea prefixului de URL, răspunsuri de model simulate, compactarea mostrelor, reîncercarea, epuizarea resurselor, respingerea și acceptarea. Testul de integrare pornește gateway-ul oficial nemodificat și un server static temporar cu fragmente generate aleator. Acesta reproduce interfața fixture-ului fără Docker. Execuția de dezvoltare a folosit Node 24. Imaginea țintește Node 22. Docker, platforma live și modelul real nu au fost testate. Dimensiunea imaginii finale nu a fost măsurată.

Starterul original permite modelului să ruleze shell, păstrează istoricul dialogului și folosește implicit 14 pași și o rezervă de 100 s. Agentul din această arhivă are un repertoriu fix de transformări și nu execută comenzi sau binare primite din probă. Nu acoperă exploatarea web, analiza dinamică sau criptografia generală. Nu există un benchmark comparativ cu Basic. STARTER-REFERENCE.md descrie kitul original și gateway-ul. Pentru comportamentul acestei variante folosește prezentul README.
