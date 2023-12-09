import os
import logging
from packetproc import *
from AIprocessor import process_sample_data
import time
from tabulate import tabulate
from Network import Net
from joblib import load
import joblib
import torch
import signal
import warnings
import argparse
from sklearn.exceptions import InconsistentVersionWarning

# Игнорирование предупреждений о несовместимой версии
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

# Настройка логирования
logging.basicConfig(level=logging.INFO)

# Обработчик сигнала для корректного завершения программы при нажатии Ctrl+C
def signal_handler(sig, frame):
    print("Выход из программы.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Функция настройки логирования с указанием пути к файлу лога
def setup_logging(log_file_path):
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    # Удаление предыдущих обработчиков логов и добавление нового
    for handler in logging.getLogger().handlers[:]:
        logging.getLogger().removeHandler(handler)

    logging.getLogger().addHandler(file_handler)

# Функция для логирования ошибок и их вывода на консоль
def log_error_and_print_to_console(error_message):
    logging.error(error_message)
    print(f"Error: {error_message}")

# Функция обработки и отображения результатов обработки данных
def process_and_display_results(sample_data, scaler, model, packet_types, source_ips, log_suspicious_only):
    result = process_sample_data(sample_data, scaler, model)

    try:
        # Вывод результатов только для подозрительных пакетов, если указан флаг
        if not log_suspicious_only or (log_suspicious_only and result['predicted_class'] == 'Suspicious'):
            logging.info("Предсказанный класс для %s пакета от %s : %s, В безопасности этого пакета модель уверена на %f%%", packet_types, source_ips, result['predicted_class'], result['confidence_normal'])
            print(f"Предсказанный класс: {result['predicted_class']}")
            print(f"Система уверена в безопасности пакета на {result['confidence_normal']}%")
            print(f"Тип обработанных пакетов: {packet_types}")
            print(f"IP отправителя: {source_ips}")
            print("\n")
    except Exception as e:
        log_error_and_print_to_console(str(e))

# Функция форматирования данных и вывода их в табличной форме
def dataframe_formating(sample_data):
    try:
        sample_data_format = tabulate(sample_data, headers='keys', tablefmt='pretty', showindex=False)
        print(sample_data_format)
    except Exception as e:
        log_error_and_print_to_console(str(e))

# Функция парсинга аргументов командной строки
def parse_args():
    parser = argparse.ArgumentParser(description="Система IDS c AI")

    parser.add_argument('--log-file', type=str, default="network_processing.log", help="Путь к файлу лога (по умолчанию в корневой директории программы)")
    parser.add_argument('--packet-type', type=str, default="all", choices=['tcp', 'udp', 'all'], help="Тип пакетов для обработки")
    parser.add_argument('--only-suspicious', type=str, default="no", choices=['yes', 'no'], help="Только подозрительные пакеты")

    return parser.parse_args()

# Основная функция программы
def main(scaler, model):
    try:
        # Парсинг аргументов командной строки
        args = parse_args()

        # Преобразование типов и установка флагов
        packet_type = args.packet_type.lower()
        log_suspicious_only = args.only_suspicious.lower() == 'yes'

        # Установка пути к файлу лога в зависимости от указанного или дефолтного значения
        if args.log_file is None:
            default_log_file_path = os.path.join(os.path.dirname(__file__), "network_processing.log")
        else:
            default_log_file_path = args.log_file

        # Настройка логирования
        setup_logging(default_log_file_path)

        # Вывод параметров запуска программы
        print(f"Программа будет запущена через 5 сек с следующими параметрами: Только подозрительные: {log_suspicious_only}, Тип обрабатываемых пакетов: {packet_type}, Путь до лог файла: {default_log_file_path}.\n Чтобы выйти из программы нажимайте CTRL+C")
        time.sleep(5)
        # Бесконечный цикл обработки данных
        while True:
            try:
                # Захват данных сетевых пакетов
                sample_data, packet_types, source_ips = capture_packets(protocol=packet_type)

                # Обработка данных, если они присутствуют
                if sample_data is not None:
                    result = process_sample_data(sample_data, scaler, model)

                    # Вывод результатов обработки, если указаны типы пакетов и флаг подозрительных пакетов
                    if packet_types and (not log_suspicious_only or (log_suspicious_only and result['predicted_class'] == 'Suspicious')):
                        dataframe_formating(sample_data)
                        process_and_display_results(sample_data, scaler, model, packet_types, source_ips, log_suspicious_only)

                time.sleep(1)

            except KeyboardInterrupt:
                logging.info("Выход из программы.")
                break
            except Exception as e:
                log_error_and_print_to_console(f"Ошибка: {str(e)}")
                continue

    except Exception as e:
        log_error_and_print_to_console(str(e))

# Запуск программы при выполнении скрипта
if __name__ == "__main__":
    try:
        # Получение пути к директории скрипта
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Загрузка необходимых данных и инициализация модели
        input_size = joblib.load(os.path.join(script_dir, 'input_size.joblib'))
        scaler = load(os.path.join(script_dir, 'scaler.joblib'))
        model = Net(input_size)
        model.load_state_dict(torch.load(os.path.join(script_dir, 'model_new.pth')))
        model.eval()
    except Exception as e:
        log_error_and_print_to_console(str(e))
    main(scaler, model)
