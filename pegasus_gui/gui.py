import os
import sys
import struct
from PyQt6 import QtWidgets, QtCore
from PyQt6.QtGui import QPixmap, QPainter, QColor
from PyQt6.QtWidgets import QGraphicsOpacityEffect
from netaddr import IPAddress, IPNetwork
import subprocess
from pathlib import Path

import fcntl

_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2

def _IOC(dir, type_, nr, size):
    return (dir << _IOC_DIRSHIFT) | (ord(type_) << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)

def _IO(type_, nr):
    return _IOC(_IOC_NONE, type_, nr, 0)

def _IOW(type_, nr, size):
    return _IOC(_IOC_WRITE, type_, nr, size)

# Types
IOCTL_MAGIC = 'P'
# sizes
UINT32_SIZE = 4
IN6_ADDR_SIZE = 16

PEGASUS_BLOCK_IP_V4 = _IOW(IOCTL_MAGIC, 0x01, UINT32_SIZE)
PEGASUS_BLOCK_IP_V6 = _IOW(IOCTL_MAGIC, 0x02, IN6_ADDR_SIZE)
PEGASUS_UNBLOCK_IP_V4 = _IOW(IOCTL_MAGIC, 0x03, UINT32_SIZE)
PEGASUS_UNBLOCK_IP_V6 = _IOW(IOCTL_MAGIC, 0x04, IN6_ADDR_SIZE)
PEGASUS_UNBLOCK_ALL_IPV4 = _IO(IOCTL_MAGIC, 0x05)
PEGASUS_UNBLOCK_ALL_IPV6 = _IO(IOCTL_MAGIC, 0x06)
PEGASUS_BLOCK_ALL_IPV4_TRAFFIC = _IO(IOCTL_MAGIC, 0x07)
PEGASUS_BLOCK_ALL_IPV6_TRAFFIC = _IO(IOCTL_MAGIC, 0x08)
PEGASUS_UNBLOCK_ALL_IPV4_TRAFFIC = _IO(IOCTL_MAGIC, 0x09)
PEGASUS_UNBLOCK_ALL_IPV6_TRAFFIC = _IO(IOCTL_MAGIC, 0x0A)
PEGASUS_BLOCK_TCP_PROTO = _IO(IOCTL_MAGIC, 0x0B)
PEGASUS_BLOCK_UDP_PROTO = _IO(IOCTL_MAGIC, 0x0C)
PEGASUS_BLOCK_ICMP_PROTO = _IO(IOCTL_MAGIC, 0x0D)
PEGASUS_BLOCK_EXCEPT_TCP_PROTO = _IO(IOCTL_MAGIC, 0x0E)
PEGASUS_BLOCK_EXCEPT_UDP_PROTO = _IO(IOCTL_MAGIC, 0x0F)
PEGASUS_BLOCK_EXCEPT_ICMP_PROTO = _IO(IOCTL_MAGIC, 0x10)
PEGASUS_PROTO_CLEAR = _IO(IOCTL_MAGIC, 0x11)
PEGASUS_BLOCK_ALL_PROTO = _IO(IOCTL_MAGIC, 0x12)

DEV_PATH = "/dev/pegasus"

def open_device():
    return open(DEV_PATH, "rb+", buffering=0)

def ioctl_noarg(fd, cmd):
    fcntl.ioctl(fd, cmd)

def ioctl_with_bytes(fd, cmd, data_bytes):
    # fcntl.ioctl requires a mutable buffer for some variants — use bytearray
    buf = bytearray(data_bytes)
    fcntl.ioctl(fd, cmd, buf)
    return buf

def ipv4_to_be32_bytes(ipv4_str):
    ip = IPAddress(ipv4_str)
    if ip.version != 4:
        raise ValueError("Not IPv4")
    packed = struct.pack("!I", int(ip))  # network byte order
    return packed

def ipv6_to_bytes(ipv6_str):
    ip = IPAddress(ipv6_str)
    if ip.version != 6:
        raise ValueError("Not IPv6")
    return ip.packed

class PegasusWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pegasus Control")
        self.resize(1200, 800)

        bg_path = Path(__file__).resolve().parent / "pegasus_image.jpg"
        if bg_path.exists():

            orig = QPixmap(str(bg_path))
            self._bg_label = QtWidgets.QLabel(self)
            self._bg_label.setPixmap(orig)
            self._bg_label.setScaledContents(True)
            self._bg_label.setGeometry(0, 0, self.width(), self.height())
            self._bg_label.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
            self._bg_label.setStyleSheet("background: transparent;")
            self._bg_label.lower()
        else:
            self._bg_label = None
        layout = QtWidgets.QVBoxLayout(self)

        # Device status
        self.dev_label = QtWidgets.QLabel(f"Device: {DEV_PATH}")
        layout.addWidget(self.dev_label)

        # IPv4 block controls
        ipv4_box = QtWidgets.QGroupBox("")
        ipv4_layout = QtWidgets.QHBoxLayout()
        self.ipv4_input = QtWidgets.QLineEdit()
        self.ipv4_input.setPlaceholderText("x.x.x.x")
        btn_block_v4 = QtWidgets.QPushButton("Block IPv4")
        btn_unblock_v4 = QtWidgets.QPushButton("Unblock IPv4")
        btn_unblock_all_v4 = QtWidgets.QPushButton("Unblock All IPv4")
        btn_block_all_v4 = QtWidgets.QPushButton("Block All IPv4 Traffic")
        btn_unblock_all_traffic_v4 = QtWidgets.QPushButton("Unblock All IPv4 Traffic")
        ipv4_layout.addWidget(self.ipv4_input)
        ipv4_layout.addWidget(btn_block_v4)
        ipv4_layout.addWidget(btn_unblock_v4)
        ipv4_layout.addWidget(btn_unblock_all_v4)
        ipv4_layout.addWidget(btn_block_all_v4)
        ipv4_layout.addWidget(btn_unblock_all_traffic_v4)
        ipv4_box.setLayout(ipv4_layout)
        layout.addWidget(ipv4_box)

        self.load_module_btn = QtWidgets.QPushButton("Load module pegasus.ko")
        layout.addWidget(self.load_module_btn)
        self.load_module_btn.clicked.connect(self.handle_load_module)
        # IPv6 block controls
        ipv6_box = QtWidgets.QGroupBox("")
        ipv6_layout = QtWidgets.QHBoxLayout()
        self.ipv6_input = QtWidgets.QLineEdit()
        self.ipv6_input.setPlaceholderText("xxxx:... or ::1")
        btn_block_v6 = QtWidgets.QPushButton("Block IPv6")
        btn_unblock_v6 = QtWidgets.QPushButton("Unblock IPv6")
        btn_unblock_all_v6 = QtWidgets.QPushButton("Unblock All IPv6")
        btn_block_all_v6 = QtWidgets.QPushButton("Block All IPv6 Traffic")
        btn_unblock_all_traffic_v6 = QtWidgets.QPushButton("Unblock All IPv6 Traffic")
        ipv6_layout.addWidget(self.ipv6_input)
        ipv6_layout.addWidget(btn_block_v6)
        ipv6_layout.addWidget(btn_unblock_v6)
        ipv6_layout.addWidget(btn_unblock_all_v6)
        ipv6_layout.addWidget(btn_block_all_v6)
        ipv6_layout.addWidget(btn_unblock_all_traffic_v6)
        ipv6_box.setLayout(ipv6_layout)
        layout.addWidget(ipv6_box)

        # Protocols
        proto_box = QtWidgets.QGroupBox("")
        proto_layout = QtWidgets.QHBoxLayout()
        btn_tcp = QtWidgets.QPushButton("Only TCP")
        btn_udp = QtWidgets.QPushButton("Only UDP")
        btn_icmp = QtWidgets.QPushButton("Only ICMP")
        btn_except_tcp = QtWidgets.QPushButton("Except TCP")
        btn_except_udp = QtWidgets.QPushButton("Except UDP")
        btn_except_icmp = QtWidgets.QPushButton("Except ICMP")
        btn_all_proto = QtWidgets.QPushButton("Set all protocol")
        btn_clear_proto = QtWidgets.QPushButton("Clear Protocol Filter")
        proto_layout.addWidget(btn_tcp)
        proto_layout.addWidget(btn_udp)
        proto_layout.addWidget(btn_icmp)
        proto_layout.addWidget(btn_except_tcp)
        proto_layout.addWidget(btn_except_udp)
        proto_layout.addWidget(btn_except_icmp)
        proto_layout.addWidget(btn_clear_proto)
        proto_layout.addWidget(btn_all_proto)
        proto_box.setLayout(proto_layout)
        layout.addWidget(proto_box)

        # Log
        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        # Connections
        btn_block_v4.clicked.connect(self.handle_block_v4)
        btn_unblock_v4.clicked.connect(self.handle_unblock_v4)
        btn_unblock_all_v4.clicked.connect(self.handle_unblock_all_v4)
        btn_block_all_v4.clicked.connect(self.handle_block_all_v4)
        btn_unblock_all_traffic_v4.clicked.connect(self.handle_unblock_all_traffic_v4)

        btn_block_v6.clicked.connect(self.handle_block_v6)
        btn_unblock_v6.clicked.connect(self.handle_unblock_v6)
        btn_unblock_all_v6.clicked.connect(self.handle_unblock_all_v6)
        btn_block_all_v6.clicked.connect(self.handle_block_all_v6)
        btn_unblock_all_traffic_v6.clicked.connect(self.handle_unblock_all_traffic_v6)

        btn_tcp.clicked.connect(lambda: self.do_ioctl_noarg(PEGASUS_BLOCK_TCP_PROTO, "Set: Only TCP"))
        btn_udp.clicked.connect(lambda: self.do_ioctl_noarg(PEGASUS_BLOCK_UDP_PROTO, "Set: Only UDP"))
        btn_icmp.clicked.connect(lambda: self.do_ioctl_noarg(PEGASUS_BLOCK_ICMP_PROTO, "Set: Only ICMP"))
        btn_except_tcp.clicked.connect(lambda: self.do_ioctl_noarg(PEGASUS_BLOCK_EXCEPT_TCP_PROTO, "Set: Except TCP"))
        btn_except_udp.clicked.connect(lambda: self.do_ioctl_noarg(PEGASUS_BLOCK_EXCEPT_UDP_PROTO, "Set: Except UDP"))
        btn_except_icmp.clicked.connect(lambda: self.do_ioctl_noarg(PEGASUS_BLOCK_EXCEPT_ICMP_PROTO, "Set: Except ICMP"))

        btn_all_proto.clicked.connect(lambda: self.do_ioctl_noarg(PEGASUS_BLOCK_ALL_PROTO, "Set: Block all proto"))
        btn_clear_proto.clicked.connect(lambda:self.do_ioctl_noarg(PEGASUS_PROTO_CLEAR, "Clear all protocols"))
        self.setStyleSheet("""
        QGroupBox { background-color: rgba(0,0,80,200); border: 1px solid rgba(0,0,0,80); border-radius:6px; }
        QPlainTextEdit { background-color: rgba(0,0,80,200); }
        QLineEdit { background-color: rgba(0,0,80,230); }
        """)


    def resizeEvent(self, event):
        super().resizeEvent(event)
        if getattr(self, "_bg_label", None):
            self._bg_label.setGeometry(0, 0, self.width(), self.height())
# rescale original pixmap to window size to avoid blurry repeats
            orig = QPixmap(str(Path(__file__).resolve().parent.parent / "pegasus_image.jpg"))
            if not orig.isNull():
                scaled = orig.scaled(self.size(), QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding, QtCore.Qt.TransformationMode.SmoothTransformation)
                self._bg_label.setPixmap(scaled)

    def log_msg(self, s):
        self.log.appendPlainText(s)

    def open_dev(self):
        try:
            f = open_device()
            return f
        except Exception as e:
            self.log_msg(f"ERROR opening device: {e}")
            return None

    # Handlers
    def handle_block_v4(self):
        ip = self.ipv4_input.text().strip()
        try:
            b = ipv4_to_be32_bytes(ip)
        except Exception as e:
            self.log_msg(f"Invalid IPv4: {e}")
            return
        f = self.open_dev()
        if not f: return
        try:
            ioctl_with_bytes(f, PEGASUS_BLOCK_IP_V4, b)
            self.log_msg(f"Blocked IPv4 {ip}")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_unblock_v4(self):
        ip = self.ipv4_input.text().strip()
        try:
            b = ipv4_to_be32_bytes(ip)
        except Exception as e:
            self.log_msg(f"Invalid IPv4: {e}")
            return
        f = self.open_dev()
        if not f: return
        try:
            ioctl_with_bytes(f, PEGASUS_UNBLOCK_IP_V4, b)
            self.log_msg(f"Unblocked IPv4 {ip}")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_unblock_all_v4(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_UNBLOCK_ALL_IPV4)
            self.log_msg("Unblocked all IPv4 addresses")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_block_all_v4(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_BLOCK_ALL_IPV4_TRAFFIC)
            self.log_msg("Blocked all IPv4 traffic")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_unblock_all_traffic_v4(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_UNBLOCK_ALL_IPV4_TRAFFIC)
            self.log_msg("Unblocked all IPv4 traffic")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_block_v6(self):
        ip = self.ipv6_input.text().strip()
        try:
            b = ipv6_to_bytes(ip)
        except Exception as e:
            self.log_msg(f"Invalid IPv6: {e}")
            return
        f = self.open_dev()
        if not f: return
        try:
            ioctl_with_bytes(f, PEGASUS_BLOCK_IP_V6, b)
            self.log_msg(f"Blocked IPv6 {ip}")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_unblock_v6(self):
        ip = self.ipv6_input.text().strip()
        try:
            b = ipv6_to_bytes(ip)
        except Exception as e:
            self.log_msg(f"Invalid IPv6: {e}")
            return
        f = self.open_dev()
        if not f: return
        try:
            ioctl_with_bytes(f, PEGASUS_UNBLOCK_IP_V6, b)
            self.log_msg(f"Unblocked IPv6 {ip}")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_unblock_all_v6(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_UNBLOCK_ALL_IPV6)
            self.log_msg("Unblocked all IPv6 addresses")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_block_all_v6(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_BLOCK_ALL_IPV6_TRAFFIC)
            self.log_msg("Blocked all IPv6 traffic")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def handle_unblock_all_traffic_v6(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_UNBLOCK_ALL_IPV6_TRAFFIC)
            self.log_msg("Unblocked all IPv6 traffic")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def set_all_flag_protocol(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_BLOCK_ALL_PROTO)
            self.log_msg("Set: true all protocols flags")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def clear_protocol_filter(self):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, PEGASUS_PROTO_CLEAR)
            self.log_msg("Clear all protocols flags")
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()

    def do_ioctl_noarg(self, cmd, msg):
        f = self.open_dev()
        if not f: return
        try:
            ioctl_noarg(f, cmd)
            self.log_msg(msg)
        except Exception as e:
            self.log_msg(f"ioctl error: {e}")
        finally:
            f.close()
    def handle_load_module(self):
    # path relative to this script
        script_dir = Path(__file__).resolve().parent
        module_path = (script_dir / ".." / "pegasus.ko").resolve()
        if not module_path.exists():
            self.log_msg(f"Module not found: {module_path}")
            return
    # try insmod first
        try:
        # use sudo if not root; prefer running insmod directly if already root
            if os.geteuid() == 0:
                cmd = ["insmod", str(module_path)]
            else:
                cmd = ["sudo", "insmod", str(module_path)]
            self.log_msg(f"Running: {' '.join(cmd)}")
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            if proc.returncode == 0:
                self.log_msg(f"Module loaded: {module_path.name}")
            else:
            # if already built into kernel or fails, show stderr
                self.log_msg(f"insmod failed (code {proc.returncode}): {proc.stderr.strip()}")
            # try modprobe fallback (module name without path)
                modname = module_path.stem
                self.log_msg(f"Trying modprobe {modname}")
                if os.geteuid() == 0:
                    cmd2 = ["modprobe", modname]
                else:
                    cmd2 = ["sudo", "modprobe", modname]
                proc2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
                if proc2.returncode == 0:
                    self.log_msg(f"modprobe succeeded: {modname}")
                else:
                    self.log_msg(f"modprobe failed (code {proc2.returncode}): {proc2.stderr.strip()}")
        except subprocess.TimeoutExpired:
            self.log_msg("Module load timed out")
        except Exception as e:
            self.log_msg(f"Error loading module: {e}")

def main():
    app = QtWidgets.QApplication(sys.argv)
    w = PegasusWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
