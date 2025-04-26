#!/usr/bin/env python
import sys
import warnings
from datetime import datetime

from crew import Cybercrew

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

def run():
    """
    Run the crew.
    """
    # Demande à l'utilisateur une cible réseau à scanner
    target = input("Entrez l'adresse IP ou le nom de domaine à scanner (par ex. scanme.nmap.org) : ")

    inputs = {
        'target': target,  # Remplacez par la cible que vous souhaitez scanner
        'current_hour': str(datetime.now().hour)
    }

    try:
        # Lancement du crew avec les inputs
        Cybercrew().crew().kickoff(inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")

if __name__ == "__main__":
    run()
