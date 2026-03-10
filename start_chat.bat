@echo off
cd /d D:\server

echo =========================
echo Запуск сервера...
echo =========================
start cmd /k node server.js

timeout /t 3 >nul

echo =========================
echo Запуск туннеля Serveo...
echo =========================
start cmd /k ssh -o ServerAliveInterval=60 -R 80:127.0.0.1:3000 serveo.net

echo =========================
echo Чат запущен
echo Ссылка появится во втором окне
echo =========================
pause
