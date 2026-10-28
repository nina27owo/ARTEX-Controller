@echo off
setlocal
chcp 936 >nul
title ARTEX 控制台
cd /d "%~dp0"

echo ============================================================
echo   ARTEX 控制台
echo   目录: %~dp0
echo ============================================================
echo.

if not exist "%~dp0artex_console.py" (
  echo [x] 当前目录下没有 artex_console.py
  echo.
  pause
  exit /b 1
)

if not exist "%~dp0config.toml" (
  if exist "%~dp0config.example.toml" (
    copy /y "%~dp0config.example.toml" "%~dp0config.toml" >nul
    echo [i] 已由 config.example.toml 生成 config.toml
    echo     需要的话先关掉本窗口，改好里面的账号密码再启动
    echo.
  ) else (
    echo [x] 当前目录下没有 config.toml（服务器、账号密码、端口都在里面）
    echo.
    pause
    exit /b 1
  )
)

set "PY="
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>nul
  if not errorlevel 1 set "PY=py -3"
)
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 (
    python -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>nul
    if not errorlevel 1 set "PY=python"
  )
)
if not defined PY (
  echo [x] 没找到 Python 3.11 或以上版本
  echo     下载地址: https://www.python.org/downloads/
  pause
  exit /b 1
)

%PY% -c "import paramiko" >nul 2>nul
if errorlevel 1 (
  echo [!] 缺少依赖 paramiko，正在安装 ...
  %PY% -m pip install -q -r "%~dp0requirements.txt" -i https://pypi.tuna.tsinghua.edu.cn/simple
  if errorlevel 1 %PY% -m pip install -q -r "%~dp0requirements.txt"
  %PY% -c "import paramiko" >nul 2>nul
  if errorlevel 1 (
    echo [x] paramiko 安装失败，请手动执行:  %PY% -m pip install -r requirements.txt
    pause
    exit /b 1
  )
)

echo [i] 启动中，浏览器窗口会自动打开控制台 ...
echo     本窗口已最小化到任务栏，关闭它即停止服务
echo.
%PY% "%~dp0artex_console.py" --minimize-console %*
set "RC=%ERRORLEVEL%"
echo.
echo 控制台已退出（代码 %RC%）
pause
exit /b %RC%
