import unittest
from scapy.all import IP, TCP
from PYTHON.Scan import detect_scan
from PYTHON.Scan import alert_queue

class TestScanDetection(unittest.TestCase):

    def test_detect_scan_syn(self):
        # Crée un paquet SYN simulé
        packet = IP(src="10.100.1.125") / TCP(flags="S")
        detect_scan(packet)
        # Vérifie que l'alerte a été ajoutée à la queue
        self.assertEqual(alert_queue.qsize(), 1)
        alert = alert_queue.get()
        self.assertEqual(alert, "[SYN Scan] Détecté de 10.100.1.125")

    def test_detect_scan_null(self):
        # Crée un paquet SYN simulé
        packet = IP(src="10.100.1.125") / TCP(flags=0)
        detect_scan(packet)
        # Vérifie que l'alerte a été ajoutée à la queue
        self.assertEqual(alert_queue.qsize(), 1)
        alert = alert_queue.get()
        self.assertEqual(alert, "[Null Scan] Détecté de 10.100.1.125")

    def test_detect_scan_xmas(self):
        # Crée un paquet SYN simulé
        packet = IP(src="10.100.1.125") / TCP(flags="FPU")
        detect_scan(packet)
        # Vérifie que l'alerte a été ajoutée à la queue
        self.assertEqual(alert_queue.qsize(), 1)
        alert = alert_queue.get()
        self.assertEqual(alert, "[Xmas Scan] Détecté de 10.100.1.125")

    def test_detect_no_scan(self):
        # Crée un paquet TCP sans flags SYN
        packet = IP(src="10.100.1.215") / TCP(flags="A")  # Flags de ACK
        detect_scan(packet)
        # Vérifie que l'alerte n'a pas été ajoutée
        self.assertEqual(alert_queue.qsize(), 0)

if __name__ == '__main__':
    unittest.main()

# python -m unittest discover -s PYTHON/Test