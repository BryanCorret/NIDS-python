import unittest
from scapy.all import IP, TCP
from PYTHON.scanSYN import detect_scan
from PYTHON.scanSYN import alert_queue

class TestScanDetection(unittest.TestCase):

    def test_detect_scan_syn(self):
        # Crée un paquet SYN simulé
        packet = IP(src="10.100.10.213") / TCP(flags="S")
        detect_scan(packet)
        # Vérifie que l'alerte a été ajoutée à la queue
        self.assertEqual(alert_queue.qsize(), 1)
        alert = alert_queue.get()
        self.assertEqual(alert, "[SYN Scan] Détecté de 10.100.10.213 ")

    def test_detect_no_scan(self):
        # Crée un paquet TCP sans flags SYN
        packet = IP(src="10.100.10.213") / TCP(flags="A")  # Flags de ACK
        detect_scan(packet)
        # Vérifie que l'alerte n'a pas été ajoutée
        self.assertEqual(alert_queue.qsize(), 0)

if __name__ == '__main__':
    unittest.main()

# python -m unittest discover -s PYTHON/Test