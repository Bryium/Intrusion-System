from Packet_Capture import PacketCapture
from Traffic_Analyzer import TrafficAnalyzer
from Detection_Engine import DetectionEngine
from Alert_System import AlertSystem
from scapy.all import IP, TCP
import queue

class IntrusionDetectionSystem:
  def __init__(self, interface="eth0"):
    self.Packet_Capture = PacketCapture()
    self.Traffic_Analyzer = TrafficAnalyzer()
    self.Detection_Engine = DetectionEngine()
    self.Alert_System = AlertSystem()

  def start(self):
    print(f"starting IDS on interface {self.interface}")
    self.Packet_Capture.start_capture(self.interface)

    while True:
      try:
        packet = self.Packet_Capture.packet_queue.get(timeout=1)
        features = self.Traffic_Analyzer.analyze_packet(packet)

        if features:
          threats = self.Detection_Engine.detect_threats(features)

          for threat in threats:
            packet_info = {
              'source_ip' : packet[IP].src,
              'destination_ip': packet[IP].dst,
              'source_port': packet[TCP].sport,
              'destination_port': packet[TCP].dport
            }

            self.Alert_System.generate_alert(threat, packet_info)

      except queue.Empty:
        continue
      except KeyboardInterrupt:
        print("Stopping IDS..")
        self.packet_capture.stop()
        break
__name__ == "__main__":
ids = IntrusionDetectionSystem()
ids.start()



