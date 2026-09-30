FROM kalilinux/kali-rolling

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        nikto \
        gobuster \
        enum4linux-ng \
        sshpass \
        python3 \
        dirb \
        wordlists \
        ca-certificates \
    && test -s /usr/share/wordlists/dirb/common.txt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY config.py jobs.py evidence.py actions.py runner.py /app/

CMD ["python3", "-u", "runner.py"]
