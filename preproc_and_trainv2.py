import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from torch.utils.data import TensorDataset, DataLoader
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import optim
from joblib import dump

#Настройки
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
#Загрузка данных
df1=pd.read_csv("D:/My AI/datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df2=pd.read_csv("D:/My AI/datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
df3=pd.read_csv("D:/My AI/datasets/Friday-WorkingHours-Morning.pcap_ISCX.csv")
df4=pd.read_csv("D:/My AI/datasets/Monday-WorkingHours.pcap_ISCX.csv")
df5=pd.read_csv("D:/My AI/datasets/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")
df6=pd.read_csv("D:/My AI/datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
df7=pd.read_csv("D:/My AI/datasets/Tuesday-WorkingHours.pcap_ISCX.csv")
df8=pd.read_csv("D:/My AI/datasets/Wednesday-workingHours.pcap_ISCX.csv")

df = pd.concat([df1,df2])
del df1,df2
df = pd.concat([df,df3])
del df3
df = pd.concat([df,df4])
del df4
df = pd.concat([df,df5])
del df5
df = pd.concat([df,df6])
del df6
df = pd.concat([df,df7])
del df7
df = pd.concat([df,df8])
del df8

selected_columns = [' Destination Port', ' Flow Duration', ' Fwd Packet Length Max', ' Fwd Packet Length Min', 'Fwd PSH Flags', 'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' Fwd Header Length',' Label']
df = df.loc[:, selected_columns]

df[' Label'] = df[' Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

print(df[' Label'].unique())

train, test = train_test_split(df, test_size=0.3)

print("Full dataset:\n")
print("Benign: " + str(df[" Label"].value_counts()[[0]].sum()))
print("Malicious: " + str(df[" Label"].value_counts()[[1]].sum()))
print("---------------")

print("Training set:\n")
print("Benign: " + str(train[" Label"].value_counts()[[0]].sum()))
print("Malicious: " + str(train[" Label"].value_counts()[[1]].sum()))
print("---------------")

print("Test set:\n")
print("Benign: " + str(test[" Label"].value_counts()[[0]].sum()))
print("Malicious: " + str(test[" Label"].value_counts()[[1]].sum()))

# Инициализируем скейлер
scaler = MinMaxScaler()

X_train = train.drop(columns=' Label')
X_test = test.drop(columns=' Label')  # Используйте 'test', а не 'train'

X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

dump(scaler, 'D:\My AI\scaler.joblib')

# Извлечем целевую переменную
y_train = train[' Label'].values
y_test = test[' Label'].values

# # Создаем классификатор случайного леса
# clf = RandomForestClassifier(n_estimators=100, random_state=0)
#
# # Обучаем модель
# clf.fit(X_train, y_train)
#
# # Выводим важность признаков
# importances = clf.feature_importances_
# features_importances = list(zip(X_train.columns, importances))
#
# # Сортируем признаки по важности в порядке убывания
# features_importances = sorted(features_importances, key=lambda x: x[1], reverse=True)
#
# for feature, importance in features_importances:
#     print(f"Feature: {feature}, Importance: {importance}")

# Преобразуем данные в тензоры PyTorch и создадим DataLoader

train_data = TensorDataset(torch.tensor(X_train).float(), torch.from_numpy(np.uint8(y_train)))
test_data = TensorDataset(torch.tensor(X_test).float(),  torch.from_numpy(np.uint8(y_test)))

train_loader = DataLoader(train_data, batch_size=32, shuffle=True)
test_loader = DataLoader(test_data, batch_size=32, shuffle=False)

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.fc1 = nn.Linear(X_train.shape[1], 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 2)


    def forward(self, x):
        x = F.sigmoid(self.fc1(x))
        x = F.sigmoid(self.fc2(x))
        x = self.fc3(x)
        return x

model = Net()

criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.01)

epochs = 10

for epoch in range(epochs):
    running_loss = 0
    for features, labels in train_loader:
        optimizer.zero_grad()
        output = model(features)
        loss = criterion(output, labels)
        loss.backward()
        optimizer.step()
        running_loss += loss.item()

    else:
        test_loss = 0
        accuracy = 0

        with torch.no_grad():
            model.eval()
            for features, labels in test_loader:
                output = model(features)
                test_loss += criterion(output, labels)
                ps = torch.exp(output)
                top_p, top_class = ps.topk(1, dim=1)
                equals = top_class == labels.view(*top_class.shape)
                accuracy += torch.mean(equals.type(torch.FloatTensor))

        model.train()

        print(f"Epoch {epoch+1}/{epochs}.. "
              f"Train loss: {running_loss/len(train_loader):.3f}.. "
              f"Test loss: {test_loss/len(test_loader):.3f}.. "
              f"Test accuracy: {accuracy/len(test_loader):.3f}")

torch.save(model.state_dict(), 'D:\My AI\model_new.pth')

from joblib import dump, load
dump(X_train.shape[1], 'D:\My AI\input_size.joblib')