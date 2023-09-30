import hashlib, hmac
from scapy.all import sniff, IP, TCP

# Мое имя
my_name = "YourName"

# Модифицированный алгоритм HMAC с использованием хеш-функции sha256
def hmac_sha256(key, message):
    hashed_key = hashlib.sha256(key.encode()).digest()
    hmac_hash = hmac.new(hashed_key, message.encode(), hashlib.sha256).digest()
    return hmac_hash.hex()

# Список целевых IP-адресов для сканирования открытых портов
targets = ["192.168.0.1", "192.168.0.2"]

# Фильтр для сниффера, чтобы отслеживать только TCP SYN пакеты
bpf_filter = "tcp[tcpflags] & (TCP_SYN) != 0"

# Функция обработки захваченного пакета
def packet_handler(packet):
    if packet.haslayer(TCP) and packet[TCP].flags & TCP_SYN:
        print("Detected TCP SYN packet:", packet.summary())

# Вычисление HMAC для каждого целевого IP-адреса и отправка на сканирование открытых портов
for target in targets:
    print(f"HMAC for {my_name}:", hmac_sha256(my_name, target))

# Запуск сниффера для отслеживания TCP SYN пакетов
sniff(filter=bpf_filter, prn=packet_handler, store=0, iface="eth0")