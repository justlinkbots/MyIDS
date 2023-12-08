import torch.nn.functional as F
import torch
import pandas as pd

# Создание пустого DataFrame с ожидаемыми столбцами
expected_columns = [' Destination Port', ' Flow Duration', ' Fwd Packet Length Max', ' Fwd Packet Length Min','Fwd PSH Flags', 'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' Fwd Header Length']
data = pd.DataFrame(columns=expected_columns)


def process_sample_data(sample_data, scaler, model):
    # Проверка на наличия данных
    if sample_data is None or sample_data.isnull().all().all():
        return

    # Применение импортированного маштабирования
    sample_data = scaler.transform(sample_data)
    # Преобразование в тензор PyTorch
    sample_data_tensor = torch.from_numpy(sample_data).float()
    output = model.forward(sample_data_tensor).data

    # Получение вероятности для каждого класса
    ps = F.softmax(output, dim=1)
    # Получение вероятности для каждого класса в процентах
    confidence_normal = ps[0][0].item() * 100
    confidence_suspicious = ps[0][1].item() * 100
    top_p, top_class = ps.topk(1, dim=1)
    # Получение метки класса
    predicted_class = "Normal" if top_class.item() == 0 else "Suspicious"

    # Возвращаем результаты в виде словаря
    return {
        "predicted_class": predicted_class,
        "confidence_normal": confidence_normal,
        "confidence_suspicious": confidence_suspicious
    }