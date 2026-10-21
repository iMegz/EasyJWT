FROM ticarpi/jwt_tool

RUN pip3 install --no-cache-dir flask

COPY webui /webui
COPY wordlists /wordlists

EXPOSE 5000

ENV PORT=5000

ENTRYPOINT ["python3", "/webui/app.py"]
