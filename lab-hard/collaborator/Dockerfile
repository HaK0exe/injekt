# lab-hard/collaborator/Dockerfile — self-hosted OOB collaborator (stdlib only).
FROM python:3.12-slim
WORKDIR /srv
COPY server.py .
EXPOSE 8080
ENTRYPOINT ["python3", "server.py"]
