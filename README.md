Блокиратор интрернет трафика.

составные части:
1) драйвер pegasus.
2) графическая прогрмма pegasus.


Драйвер реализован на Си, перехватывает входящие пакеты на сетевом уровне OSI и реализует взаимодействие с пользовательским процессом через символическое устройство и вызовы ioctl.
Предоставляет опции такие как:
1) Блокировние пакетов с определенных ip адресос (как ipv4 так и ipv6)
2) Блокирование по транспортному протоколу (TCP, UDP, ICMP)


Графическая часть реализованно на Питоне с использованим библиотеки PyQt6.
Предоставляет опции такие как:
1) Графический интерфейс
2) Взаимодействие с драйвером


Пример работы:
1) Установка:  ```git clone https://github.com/JOKKEU/pegasus ```
<img width="1008" height="366" alt="image" src="https://github.com/user-attachments/assets/140814f8-11cd-4f9b-b154-a30f410f8b02" />

2) Сборка драйвера: ``` cd pegasus && make ```
<img width="1762" height="368" alt="image" src="https://github.com/user-attachments/assets/c95dbae0-0e9f-451d-ae66-49a3f52dbcca" />

3) Установка зависимостей:
```

    Установка через пакетный менеджер (Debian/Ubuntu):

    sudo apt update && sudo apt install libgl1

    Fedora / RHEL:

    sudo dnf install mesa-libGL

    Arch:

    sudo pacman -Syu mesa
```


4) Установка зависимостей питона:
```
Python 3.8+
PyQt6: pip install PyQt6
pip install netaddr (для валидации IP)
```

5) Запуск графисеского приложения:
```
NIXOS: sudo nix-shell -p '(pkgs.python310.withPackages (ps: with ps; [ pyqt6 ps.netaddr ]))' mesa --run "python3 gui.py"
other distrib: sudo python3 ./gui.py
```
Графическое приложение:
<img width="1209" height="829" alt="image" src="https://github.com/user-attachments/assets/121e5112-a417-4eff-8334-d138203c1436" />

Нажимаем Load module pegasus.ko

<img width="638" height="78" alt="image" src="https://github.com/user-attachments/assets/3fb63f2a-458f-49a3-b7aa-d125f71065e5" />

Завершение работы: нажимаем module unload и закрываем программу.

<img width="323" height="79" alt="image" src="https://github.com/user-attachments/assets/a8c52f72-371b-421f-aac5-791a2ac65f4f" />





