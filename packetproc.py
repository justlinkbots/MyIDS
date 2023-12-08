import pandas as pd
import numpy as np
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

def packet_process(packet, protocol=None):
    if not packet.haslayer(IP):
        return None, None, None  # Добавляем еще один None для IP отправителя

    # Инициализация необходимых переменных и присваивание им значений по-умолчанию
    protocol_type = None
    destination_port = None
    flow_start_time = None
    flow_end_time = None
    fwd_packet_len_max = None
    fwd_packet_len_min = None
    fwd_psh_flag = 0
    fin_flag_count = 0
    syn_flag_count = 0
    rst_flag_count = 0
    fwd_header_len = None

    try:
        # Проверка протокола
        protocol_type = packet[IP].proto
        if protocol_type == 6:  # TCP
            protocol_type = 'tcp'
        elif protocol_type == 17:  # UDP
            protocol_type = 'udp'
        else:
            return None, None, None  # Игнорировать ненужные протоколы

        # Проверка, обрабатывать ли данный протокол
        if protocol and protocol != 'all' and protocol != protocol_type:
            return None, None, None

        # Инициализация времени начала потока
        flow_start_time = time.time()

        # Получение IP отправителя
        source_ip = packet[IP].src

        # Если протокол TCP
        if protocol_type == 'tcp':
            destination_port = packet[TCP].dport
            fwd_packet_len_max = len(packet[TCP].payload)
            fwd_packet_len_min = len(packet[TCP].payload)
            fwd_psh_flag = int('P' in str(packet[TCP].flags))
            fin_flag_count = int('F' in str(packet[TCP].flags))
            syn_flag_count = int('S' in str(packet[TCP].flags))
            rst_flag_count = int('R' in str(packet[TCP].flags))
            fwd_header_len = len(packet[TCP])

        # Если протокол UDP
        elif protocol_type == 'udp':
            destination_port = packet[UDP].dport
            fwd_packet_len_max = len(packet[UDP].payload)
            fwd_packet_len_min = len(packet[UDP].payload)
            fwd_header_len = len(packet[UDP])

        # Инициализация времени окончания потока
        flow_end_time = time.time()
        flow_duration = round((flow_end_time - flow_start_time) * 1000000)

    # Обработка исключений
    except Exception as e:
        print(str(e))
        return None, None, None

    # Создание словаря с нужными данными
    new_row = {' Destination Port': destination_port,
               ' Flow Duration': flow_duration,
               ' Fwd Packet Length Max': fwd_packet_len_max,
               ' Fwd Packet Length Min': fwd_packet_len_min,
               'Fwd PSH Flags': fwd_psh_flag,
               'FIN Flag Count': fin_flag_count,
               ' SYN Flag Count': syn_flag_count,
               ' RST Flag Count': rst_flag_count,
               ' Fwd Header Length': fwd_header_len}
    return new_row, protocol_type, source_ip  # Возврат словаря, типа пакета и IP отправителя


def capture_packets(protocol=None):
    packets = sniff(count=1, iface=r"Ethernet")  # Захват пакета с интерфейса Ethernet
    data_rows = []  # Создание пустого массива
    packet_types = set()  # Множество для хранения типов пакетов
    source_ips = set()  # Множество для хранения IP отправителей
    for packet in packets:  # Цикл для прохода по пакетам
        processed_packet, packet_type, source_ip = packet_process(packet, protocol)  # Вызов функции
        if processed_packet is not None:  # Проверка на наличия данных
            data_rows.append(processed_packet)  # Добавление в датафрейм пакета
            if packet_type:
                packet_types.add(packet_type)  # Добавление типа пакета в множество
            if source_ip:
                source_ips.add(source_ip)  # Добавление IP отправителя в множество
    if not data_rows:  # Пропуск, если data_rows пуст
        return None, None, None
    new_data = pd.DataFrame(data_rows)  # Представление массива как датафрейм
    return new_data, packet_types, source_ips  # Возврат готового датафрейма, множества типов пакетов и множества IP отправителей
