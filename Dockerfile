FROM ticarpi/jwt_tool

RUN pip3 install --no-cache-dir flask

# Pre-create jwt_tool's config file at build time so the first request a
# container handles never hits its interactive first-run setup message.
RUN python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U >/dev/null 2>&1 || true

COPY webui /webui
COPY wordlists /wordlists

EXPOSE 5000

ENV PORT=5000

ENTRYPOINT ["python3", "/webui/app.py"]
