FROM mcr.microsoft.com/windows/servercore:1809

RUN mkdir C:\\nmiwindows

WORKDIR C:\\nmiwindows

COPY nmi.exe C:\\nmiwindows\\nmi_windows.exe

ENTRYPOINT ["C:\\nmiwindows\\nmi_windows.exe"]