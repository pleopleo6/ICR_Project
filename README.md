# Secure Messaging System

Un système de messagerie sécurisé permettant l'envoi de messages et fichiers chiffrés avec accès temporisé.

## Prérequis

- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)

## Installation

1. Cloner le repository :
```bash
git clone <repository-url>
cd <repository-name>
```

2. Créer un environnement virtuel :
```bash
python -m venv venv
source venv/bin/activate  # Sur Windows : venv\Scripts\activate
```

3. Installer les dépendances :
```bash
pip install -r requirements.txt
```

## Génération des certificats SSL

Pour une communication sécurisée, générez les certificats SSL :
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365
```

## Exécution du programme

1. Démarrer le serveur :
```bash
python server.py
```

2. Dans un autre terminal, démarrer l'application web :
```bash
python app.py
```

L'application sera accessible à l'adresse : `http://localhost:5050`

## Utilisation

1. Créer un compte :
   - Accéder à la page de connexion
   - Cliquer sur "Create new account"
   - Suivre le processus d'inscription

2. Se connecter :
   - Entrer votre nom d'utilisateur et mot de passe
   - Vous serez redirigé vers le tableau de bord

3. Envoyer un message :
   - Choisir entre message texte ou fichier
   - Entrer le nom d'utilisateur du destinataire
   - Définir la date de déverrouillage (DD:MM:YYYY:HH:MM:SS)
   - Cliquer sur "Send Message"

4. Consulter les messages :
   - Cliquer sur "View Messages" dans le tableau de bord
   - Les messages seront affichés s'ils sont déverrouillés

## Features

- User authentication with secure password management
- Encrypted message sending (text and files)
- Time-locked message access
- Secure session management
- File upload support
- Password change functionality
- Message retrieval system

## Configuration

1. Place the certificates in the project root directory:
- `server.crt`
- `server.key`

## Security Features

- Session management with automatic expiration (15 minutes)
- HTTP-only cookies
- CSRF protection
- Secure password storage
- Encrypted message transmission
- Time-locked message access

## Development Notes

This is a Proof of Concept (POC) implementation. For production use, consider:

1. Moving configuration to environment variables
2. Implementing a more robust session management system
3. Adding rate limiting
4. Implementing proper error handling
5. Adding logging
6. Setting up proper HTTPS configuration

## Project Structure

```
.
├── app.py              # Web application
├── server.py           # Backend server
├── client.py           # Client utilities
├── server.crt          # SSL certificate
├── server.key          # SSL private key
└── templates/          # HTML templates
    ├── login.html
    ├── dashboard.html
    ├── send_message.html
    └── ...
```