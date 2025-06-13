from Packet_Capture import PacketCapture
from Traffic_Analyzer import TrafficAnalyzer
from Detection_Engine import DetectionEngine
from Alert_System import AlertSystem
from scapy.all import IP, TCP
import queue
from dotenv import load_dotenv
import os

load_dotenv()


class IntrusionDetectionSystem:
    def __init__(self, interface):
        self.interface         = interface
        self.packet_capture    = PacketCapture()
        self.traffic_analyzer  = TrafficAnalyzer()
        self.detection_engine  = DetectionEngine()
        self.alert_system      = AlertSystem()

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    threats = self.detection_engine.detect_threats(features)
                    for threat in threats:
                        pkt_info = {
                            'source_ip'      : packet[IP].src,
                            'destination_ip' : packet[IP].dst,
                            'source_port'    : packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, pkt_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS…")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    interface = os.getenv("INTERFACE")
    if not interface:
        raise ValueError("INTERFACE not set in .env file")
    
    ids = IntrusionDetectionSystem(interface=interface)
    ids.start()
